# Disposable local-only plan/apply fixture: no cloud provider or credentials.
terraform {
  required_version = "= 1.10.6"
}

resource "terraform_data" "approval_control" {
  input = {
    message = "MK_PLAN_PRIVATE_CANARY_20261022"
    scope   = "local plan encryption and exact-byte apply test only"
  }
}
