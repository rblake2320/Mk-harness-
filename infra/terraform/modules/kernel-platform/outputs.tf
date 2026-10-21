output "vpc_id" { value = aws_vpc.this.id }
output "alb_dns_name" { value = aws_lb.this.dns_name }
output "db_endpoint" { value = aws_db_instance.kernel.address }
output "redis_primary_endpoint" { value = aws_elasticache_replication_group.queue.primary_endpoint_address }
output "evidence_bucket" { value = aws_s3_bucket.evidence.bucket }
output "secret_arns" {
  description = "Empty secrets to populate out of band (see README)."
  value       = { for k, s in aws_secretsmanager_secret.this : k => s.arn }
}
output "prometheus_workspace_id" { value = aws_prometheus_workspace.this.id }
output "alerts_topic_arn" { value = aws_sns_topic.alerts.arn }
output "acm_validation_records" {
  value = [for o in aws_acm_certificate.this.domain_validation_options : { name = o.resource_record_name, type = o.resource_record_type, value = o.resource_record_value }]
}
