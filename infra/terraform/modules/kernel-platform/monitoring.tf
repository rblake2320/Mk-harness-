# External uptime check on the core workflow host (not the health endpoint
# alone — contract O3 availability is measured on the real path), paging via SNS.
resource "aws_sns_topic" "alerts" {
  name              = "${local.name}-alerts"
  kms_master_key_id = aws_kms_key.secrets.id
  tags              = local.tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_route53_health_check" "app" {
  fqdn              = var.approval_rp_id
  port              = 443
  type              = "HTTPS"
  resource_path     = "/api/health/ready" # database + kernel readiness (backend/app/main.py)
  failure_threshold = 3
  request_interval  = 30
  measure_latency   = true
  tags              = merge(local.tags, { Name = "${local.name}-app" })
}

resource "aws_cloudwatch_metric_alarm" "app_down" {
  alarm_name          = "${local.name}-app-unreachable"
  namespace           = "AWS/Route53"
  metric_name         = "HealthCheckStatus"
  dimensions          = { HealthCheckId = aws_route53_health_check.app.id }
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "breaching"
  tags                = local.tags
}

# Saturation alarms for the managed stores (O6 "DB/Redis/resource saturation").
resource "aws_cloudwatch_metric_alarm" "db_cpu" {
  alarm_name          = "${local.name}-db-cpu"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.kernel.identifier }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = local.tags
}

resource "aws_cloudwatch_metric_alarm" "db_storage" {
  alarm_name          = "${local.name}-db-free-storage"
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.kernel.identifier }
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10 * 1024 * 1024 * 1024
  comparison_operator = "LessThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = local.tags
}

resource "aws_cloudwatch_metric_alarm" "redis_memory" {
  alarm_name          = "${local.name}-redis-memory"
  namespace           = "AWS/ElastiCache"
  metric_name         = "DatabaseMemoryUsagePercentage"
  dimensions          = { ReplicationGroupId = aws_elasticache_replication_group.queue.id }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  threshold           = 75
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = local.tags
}

# Prometheus for the kernel's own metrics (deploy/observability): managed
# workspace + rule file. The ECS Prometheus collector (ADOT sidecar/service)
# scrapes kernel-worker:9100 and kernel-api:8090 and remote-writes here.
resource "aws_prometheus_workspace" "this" {
  alias = local.name
  tags  = local.tags
}

resource "aws_prometheus_rule_group_namespace" "kernel" {
  name         = "mk-kernel"
  workspace_id = aws_prometheus_workspace.this.id
  data         = file("${path.module}/../../../../deploy/observability/alerts.yml")
}

resource "aws_prometheus_alert_manager_definition" "this" {
  workspace_id = aws_prometheus_workspace.this.id
  definition   = <<-EOT
    alertmanager_config: |
      route:
        receiver: sns
        group_by: [alertname]
        routes:
          - matchers: [severity="page"]
            receiver: sns
            repeat_interval: 15m
      receivers:
        - name: sns
          sns_configs:
            - topic_arn: ${aws_sns_topic.alerts.arn}
              sigv4:
                region: ${var.region}
  EOT
}
