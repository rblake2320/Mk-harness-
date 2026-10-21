# Task roles: one per process type, each may read ONLY its own secrets.
data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

locals {
  # process → secrets it may read (keys of local.secret_names)
  process_secrets = {
    kernel_api    = ["master_key", "kek", "db_api_password"]
    kernel_worker = ["master_key", "kek", "db_worker_password"]
    kernel_relay  = ["db_relay_password"]
    verifier      = ["db_readonly_password"]
    app           = ["master_key", "assertion_private", "jwt_secret", "db_app_password", "stripe"]
    migrator      = ["master_key", "kek", "db_api_password", "db_worker_password", "db_relay_password", "db_readonly_password"]
  }
}

resource "aws_iam_role" "task" {
  for_each           = local.process_secrets
  name               = "${local.name}-task-${replace(each.key, "_", "-")}"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "task_secrets" {
  for_each = local.process_secrets
  role     = aws_iam_role.task[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [for s in each.value : aws_secretsmanager_secret.this[s].arn]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.secrets.arn
      }
    ]
  })
}

# Only the verifier and the restore operator may write evidence objects; no task may delete.
resource "aws_iam_role_policy" "evidence_write" {
  for_each = toset(["verifier", "kernel_api"])
  role     = aws_iam_role.task[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:PutObject", "s3:PutObjectRetention"], Resource = "${aws_s3_bucket.evidence.arn}/*" },
      { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Encrypt"], Resource = aws_kms_key.data.arn },
      { Effect = "Deny", Action = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutBucketPolicy", "s3:PutObjectLegalHold"], Resource = "*" }
    ]
  })
}

resource "aws_iam_role" "execution" {
  name               = "${local.name}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = [for s in aws_secretsmanager_secret.this : s.arn] },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.secrets.arn }
    ]
  })
}

resource "aws_iam_role" "rds_monitoring" {
  name = "${local.name}-rds-monitoring"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "monitoring.rds.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_iam_role" "flow" {
  name = "${local.name}-vpc-flow"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "flow" {
  role = aws_iam_role.flow.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"], Resource = "*" }]
  })
}
