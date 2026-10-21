# Multi-AZ PostgreSQL with PITR and replicated Redis (contract O1, O3: RPO ≤ 5 min).
resource "aws_db_subnet_group" "this" {
  name       = local.name
  subnet_ids = aws_subnet.data[*].id
  tags       = local.tags
}

resource "aws_db_parameter_group" "pg16" {
  name   = "${local.name}-pg16"
  family = "postgres16"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
  parameter {
    # pg_advisory_xact_lock-heavy control path (C6) — keep lock waits visible.
    name  = "log_lock_waits"
    value = "1"
  }
  tags = local.tags
}

resource "random_password" "db_master" {
  length  = 40
  special = false
}

resource "aws_db_instance" "kernel" {
  identifier                          = "${local.name}-pg"
  engine                              = "postgres"
  engine_version                      = "16"
  instance_class                      = var.db_instance_class
  allocated_storage                   = 100
  max_allocated_storage               = 1000
  storage_type                        = "gp3"
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.data.arn
  db_name                             = "mkharness"
  username                            = "mk_owner"
  password                            = random_password.db_master.result # rotated to Secrets Manager–managed after bootstrap (manage_master_user_password)
  multi_az                            = true
  db_subnet_group_name                = aws_db_subnet_group.this.name
  vpc_security_group_ids              = [aws_security_group.db.id]
  parameter_group_name                = aws_db_parameter_group.pg16.name
  backup_retention_period             = local.is_prod ? 35 : 7 # PITR window; RPO ≤ 5 min comes from continuous WAL archiving
  backup_window                       = "06:00-07:00"
  maintenance_window                  = "Sun:07:30-Sun:08:30"
  deletion_protection                 = local.is_prod
  skip_final_snapshot                 = !local.is_prod
  final_snapshot_identifier           = local.is_prod ? "${local.name}-final" : null
  copy_tags_to_snapshot               = true
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = aws_kms_key.data.arn
  monitoring_interval                 = 60
  monitoring_role_arn                 = aws_iam_role.rds_monitoring.arn
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
  auto_minor_version_upgrade          = true
  apply_immediately                   = !local.is_prod
  iam_database_authentication_enabled = false # per-process logins come from deploy/kernel/roles.sql
  publicly_accessible                 = false
  tags                                = local.tags
}

resource "aws_elasticache_subnet_group" "this" {
  name       = local.name
  subnet_ids = aws_subnet.data[*].id
  tags       = local.tags
}

resource "aws_elasticache_replication_group" "queue" {
  replication_group_id       = "${local.name}-redis"
  description                = "Dispatch stream (at-least-once; the outbox in PostgreSQL is the source of truth — Redis is never restored from backup)"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = var.redis_node_type
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true
  subnet_group_name          = aws_elasticache_subnet_group.this.name
  security_group_ids         = [aws_security_group.redis.id]
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  kms_key_id                 = aws_kms_key.data.arn
  snapshot_retention_limit   = 0 # deliberate: see description; stranded_queued sweep republishes from the outbox
  apply_immediately          = !local.is_prod
  tags                       = local.tags
}
