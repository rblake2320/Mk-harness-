terraform {
  required_version = ">= 1.6"
  backend "s3" {
    # Separate state per environment in the staging account; bucket created out of band
    # with versioning + SSE-KMS + object lock. Never share state between environments.
    bucket         = "mk-staging-tfstate-REPLACE_ACCOUNT_ID"
    key            = "kernel-platform/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "mk-staging-tflock"
    encrypt        = true
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Environment = "staging" }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}
variable "kernel_image" { type = string }
variable "app_image" { type = string }
variable "alert_email" { type = string }


module "platform" {
  source                = "../../modules/kernel-platform"
  environment           = "staging"
  region                = var.region
  azs                   = ["${var.region}a", "${var.region}b"]
  kernel_image          = var.kernel_image
  app_image             = var.app_image
  public_webhook_domain = "hooks.staging.consultantstudio.example"
  approval_rp_id        = "app.staging.consultantstudio.example"
  approval_origins      = ["https://app.staging.consultantstudio.example"]
  twilio_api_base       = "https://twilio-sim.staging.internal"
  alert_email           = var.alert_email

}

output "platform" {
  value     = module.platform
  sensitive = false
}
