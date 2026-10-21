variable "environment" {
  description = "production | staging — selects guardrails; the two must live in different AWS accounts and state backends."
  type        = string
  validation {
    condition     = contains(["production", "staging"], var.environment)
    error_message = "environment must be production or staging"
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "azs" {
  description = "Exactly two availability zones (contract O1: 2 AZs)."
  type        = list(string)
  validation {
    condition     = length(var.azs) == 2
    error_message = "two availability zones are required"
  }
}

variable "kernel_image" {
  description = "Immutable image reference (digest, not tag) built from deploy/kernel/Dockerfile."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.kernel_image))
    error_message = "kernel_image must be pinned by digest (…@sha256:…)"
  }
}

variable "app_image" {
  description = "Immutable image reference for the FastAPI application."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.app_image))
    error_message = "app_image must be pinned by digest"
  }
}

variable "api_desired_count" {
  type    = number
  default = 2
  validation {
    condition     = var.api_desired_count >= 2
    error_message = "contract O1: at least two API instances"
  }
}

variable "worker_desired_count" {
  type    = number
  default = 2
  validation {
    condition     = var.worker_desired_count >= 2
    error_message = "contract O1: at least two worker instances"
  }
}

variable "public_webhook_domain" {
  description = "Hostname the provider calls (MK_PUBLIC_WEBHOOK_BASE = https://<this>)."
  type        = string
}

variable "approval_rp_id" {
  description = "WebAuthn relying-party id = the approval UI's effective domain."
  type        = string
}

variable "approval_origins" {
  description = "Exact https origins allowed in clientDataJSON."
  type        = list(string)
}

variable "twilio_api_base" {
  description = "https://api.twilio.com in production; the simulator URL in staging. Guardrail: staging may not point at the live API unless allow_live_provider_in_staging is true."
  type        = string
}

variable "allow_live_provider_in_staging" {
  type    = bool
  default = false
}

variable "db_instance_class" {
  type    = string
  default = "db.r6g.large"
}

variable "redis_node_type" {
  type    = string
  default = "cache.r6g.large"
}

variable "audit_root_kms_key_arn" {
  description = "KMS key in the *separate* audit account that protects the audit-root bucket. Required in production so the audit root is independently protected from this account's administrators."
  type        = string
  default     = ""
}

variable "audit_root_bucket_arn" {
  description = "Bucket in the separate audit account that receives audit heads and evidence bundles (replication destination)."
  type        = string
  default     = ""
}

variable "alert_email" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  name = "mk-${var.environment}"
  tags = merge(var.tags, {
    Project     = "consultant-studio"
    Environment = var.environment
    ManagedBy   = "terraform"
  })
  is_prod = var.environment == "production"
}

# Guardrails evaluated at plan time (terraform >= 1.5 `check` blocks).
check "staging_provider_guard" {
  assert {
    condition     = local.is_prod || var.twilio_api_base != "https://api.twilio.com" || var.allow_live_provider_in_staging
    error_message = "staging points MK_TWILIO_API_BASE at the live provider; set allow_live_provider_in_staging=true only for a supervised provider qualification run"
  }
}

check "audit_root_guard" {
  assert {
    condition     = !local.is_prod || (var.audit_root_bucket_arn != "" && var.audit_root_kms_key_arn != "")
    error_message = "production requires audit_root_bucket_arn and audit_root_kms_key_arn from the separate audit account (contract O1/S7)"
  }
}
