# ECS Fargate across two AZs (contract O1): ≥2 API, ≥2 worker, 2 relay, 2 app
# tasks; the audit verifier and the migrator are scheduled / one-shot tasks.
# Every task: read-only root filesystem, no privilege escalation, non-root.
resource "aws_ecs_cluster" "this" {
  name = local.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = local.tags
}

resource "aws_cloudwatch_log_group" "tasks" {
  name              = "/mk/${var.environment}/tasks"
  retention_in_days = local.is_prod ? 400 : 30
  kms_key_id        = aws_kms_key.logs.arn
  tags              = local.tags
}

locals {
  db_host   = aws_db_instance.kernel.address
  redis_url = "rediss://${aws_elasticache_replication_group.queue.primary_endpoint_address}:6379"
  log_config = {
    logDriver = "awslogs"
    options = {
      awslogs-group         = aws_cloudwatch_log_group.tasks.name
      awslogs-region        = var.region
      awslogs-stream-prefix = "mk"
    }
  }
  secret = { for k, s in aws_secretsmanager_secret.this : k => s.arn }

  # The binaries compose MK_DATABASE_URL from these (mk_store::database_url_from_env),
  # so no URL containing a password ever appears in a task definition.
  common_kernel_env = [
    { name = "MK_PUBLIC_WEBHOOK_BASE", value = "https://${var.public_webhook_domain}" },
    { name = "MK_KEK_ID", value = "kek-${var.environment}-1" },
    { name = "MK_LEGACY_SEAL_RETIRED", value = "1" },
    { name = "MK_DB_HOST", value = local.db_host },
    { name = "MK_DB_NAME", value = "mkharness" },
    { name = "RUST_LOG", value = "info" },
  ]

  containers = {
    kernel_api = {
      image   = var.kernel_image
      command = ["/usr/local/bin/mk-action-api"]
      port    = 8090
      env = concat(local.common_kernel_env, [
        { name = "MK_BIND", value = "0.0.0.0:8090" },
        { name = "MK_APPROVAL_RP_ID", value = var.approval_rp_id },
        { name = "MK_APPROVAL_ORIGINS", value = join(",", var.approval_origins) },
        { name = "MK_DB_USER", value = "mk_api_login" },
        # RUST_ACTION_KERNEL_ENABLED is deliberately NOT set here: enabling is the
        # release owner's step (deploy/kernel/README.md enable sequence).
      ])
      secrets = [
        { name = "MK_MASTER_KEY", valueFrom = local.secret["master_key"] },
        { name = "MK_KEK", valueFrom = local.secret["kek"] },
        { name = "MK_DB_PASSWORD", valueFrom = local.secret["db_api_credential"] },
      ]
    }
    kernel_worker = {
      image   = var.kernel_image
      command = ["/usr/local/bin/mk-action-worker"]
      port    = 9100
      env = concat(local.common_kernel_env, [
        { name = "MK_REDIS_URL", value = local.redis_url },
        { name = "MK_TWILIO_API_BASE", value = var.twilio_api_base },
        { name = "MK_EGRESS_AUTHORITIES", value = "api.twilio.com" },
        { name = "MK_METRICS_BIND", value = "0.0.0.0:9100" },
        { name = "MK_DB_USER", value = "mk_worker_login" },
      ])
      secrets = [
        { name = "MK_MASTER_KEY", valueFrom = local.secret["master_key"] },
        { name = "MK_KEK", valueFrom = local.secret["kek"] },
        { name = "MK_DB_PASSWORD", valueFrom = local.secret["db_worker_credential"] },
      ]
    }
    kernel_relay = {
      image   = var.kernel_image
      command = ["/usr/local/bin/mk-outbox-relay"]
      port    = null
      env = concat(local.common_kernel_env, [
        { name = "MK_REDIS_URL", value = local.redis_url },
        { name = "MK_DB_USER", value = "mk_relay_login" },
      ])
      secrets = [{ name = "MK_DB_PASSWORD", valueFrom = local.secret["db_relay_credential"] }]
    }
    app = {
      image   = var.app_image
      command = null
      port    = 8000
      env = [
        { name = "RUST_ACTION_KERNEL_URL", value = "http://kernel-api.${local.name}.local:8090" },
        { name = "KERNEL_ASSERTION_KID", value = "k1" },
        { name = "DB_HOST", value = local.db_host },
      ]
      secrets = [
        { name = "MASTER_KEY", valueFrom = local.secret["master_key"] },
        { name = "KERNEL_ASSERTION_PRIVATE_KEY", valueFrom = local.secret["assertion_private"] },
        { name = "JWT_SECRET", valueFrom = local.secret["jwt_secret"] },
        { name = "DB_PASSWORD", valueFrom = local.secret["db_app_credential"] },
      ]
    }
  }
  desired = {
    kernel_api    = var.api_desired_count
    kernel_worker = var.worker_desired_count
    kernel_relay  = 2
    app           = 2
  }
}

resource "aws_ecs_task_definition" "svc" {
  for_each                 = local.containers
  family                   = "${local.name}-${replace(each.key, "_", "-")}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task[each.key].arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  container_definitions = jsonencode([{
    name                   = each.key
    image                  = each.value.image
    command                = each.value.command
    essential              = true
    readonlyRootFilesystem = true
    user                   = "65532:65532"
    linuxParameters        = { capabilities = { drop = ["ALL"] }, initProcessEnabled = true }
    portMappings           = each.value.port == null ? [] : [{ containerPort = each.value.port, protocol = "tcp" }]
    environment            = each.value.env
    secrets                = each.value.secrets
    logConfiguration       = local.log_config
    healthCheck = each.value.port == null ? null : {
      command     = ["CMD", "/usr/local/bin/mk-healthcheck", "http://127.0.0.1:${each.value.port}/health/live"]
      interval    = 15
      timeout     = 5
      retries     = 3
      startPeriod = 20
    }
  }])
  tags = local.tags
}

resource "aws_service_discovery_private_dns_namespace" "this" {
  name = "${local.name}.local"
  vpc  = aws_vpc.this.id
  tags = local.tags
}

resource "aws_service_discovery_service" "kernel_api" {
  name = "kernel-api"
  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.this.id
    dns_records {
      ttl  = 10
      type = "A"
    }
    routing_policy = "MULTIVALUE"
  }
  health_check_custom_config {
    failure_threshold = 1
  }
  tags = local.tags
}

resource "aws_ecs_service" "svc" {
  for_each                           = local.containers
  name                               = replace(each.key, "_", "-")
  cluster                            = aws_ecs_cluster.this.id
  task_definition                    = aws_ecs_task_definition.svc[each.key].arn
  desired_count                      = local.desired[each.key]
  launch_type                        = "FARGATE"
  platform_version                   = "LATEST"
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  enable_execute_command             = false
  propagate_tags                     = "SERVICE"
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  network_configuration {
    subnets          = aws_subnet.private[*].id
    assign_public_ip = false
    security_groups = [
      each.key == "app" ? aws_security_group.app.id :
      each.key == "kernel_worker" ? aws_security_group.kernel_worker.id :
      aws_security_group.kernel_api.id
    ]
  }
  dynamic "service_registries" {
    for_each = each.key == "kernel_api" ? [1] : []
    content {
      registry_arn = aws_service_discovery_service.kernel_api.arn
    }
  }
  dynamic "load_balancer" {
    for_each = each.key == "app" ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.app.arn
      container_name   = "app"
      container_port   = 8000
    }
  }
  dynamic "load_balancer" {
    for_each = each.key == "kernel_api" ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.webhooks.arn
      container_name   = "kernel_api"
      container_port   = 8090
    }
  }
  lifecycle {
    ignore_changes = [desired_count]
  }
  tags = local.tags
}

# Daily full-chain audit verification (mk-audit-verifier, read-only login).
resource "aws_ecs_task_definition" "verifier" {
  family                   = "${local.name}-verifier"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task["verifier"].arn
  container_definitions = jsonencode([{
    name                   = "verifier"
    image                  = var.kernel_image
    command                = ["/usr/local/bin/mk-audit-verifier"]
    essential              = true
    readonlyRootFilesystem = true
    user                   = "65532:65532"
    environment            = concat(local.common_kernel_env, [{ name = "MK_DB_USER", value = "mk_readonly_login" }, { name = "MK_EVIDENCE_BUCKET", value = aws_s3_bucket.evidence.bucket }])
    secrets                = [{ name = "MK_DB_PASSWORD", valueFrom = local.secret["db_readonly_credential"] }]
    logConfiguration       = local.log_config
  }])
  tags = local.tags
}

resource "aws_cloudwatch_event_rule" "verifier" {
  name                = "${local.name}-verifier-daily"
  schedule_expression = "cron(15 5 * * ? *)"
  tags                = local.tags
}

resource "aws_iam_role" "events" {
  name = "${local.name}-events"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "events.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "events" {
  role = aws_iam_role.events.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ecs:RunTask"], Resource = aws_ecs_task_definition.verifier.arn },
      { Effect = "Allow", Action = ["iam:PassRole"], Resource = [aws_iam_role.execution.arn, aws_iam_role.task["verifier"].arn] }
    ]
  })
}

resource "aws_cloudwatch_event_target" "verifier" {
  rule     = aws_cloudwatch_event_rule.verifier.name
  arn      = aws_ecs_cluster.this.arn
  role_arn = aws_iam_role.events.arn
  ecs_target {
    task_definition_arn = aws_ecs_task_definition.verifier.arn
    launch_type         = "FARGATE"
    task_count          = 1
    network_configuration {
      subnets          = aws_subnet.private[*].id
      security_groups  = [aws_security_group.kernel_api.id]
      assign_public_ip = false
    }
  }
}
