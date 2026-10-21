terraform {
  required_version = ">= 1.6"
  backend "s3" {
    # Separate state per environment in the production account; bucket created out of band
    # with versioning + SSE-KMS + object lock. Never share state between environments.
    bucket         = "mk-production-tfstate-REPLACE_ACCOUNT_ID"
    key            = "kernel-platform/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "mk-production-tflock"
    encrypt        = true
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Environment = "production" }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}
variable "kernel_image" { type = string }
variable "app_image" { type = string }
variable "alert_email" { type = string }
variable "audit_root_bucket_arn" { type = string }
variable "audit_root_kms_key_arn" { type = string }

module "platform" {
  source                 = "../../modules/kernel-platform"
  environment            = "production"
  region                 = var.region
  azs                    = ["${var.region}a", "${var.region}b"]
  kernel_image           = var.kernel_image
  app_image              = var.app_image
  public_webhook_domain  = "hooks.consultantstudio.example"
  approval_rp_id         = "app.consultantstudio.example"
  approval_origins       = ["https://app.consultantstudio.example"]
  twilio_api_base        = "https://api.twilio.com"
  alert_email            = var.alert_email
  audit_root_bucket_arn  = var.audit_root_bucket_arn
  audit_root_kms_key_arn = var.audit_root_kms_key_arn
}

output "platform" {
  value     = module.platform
  sensitive = false
}
