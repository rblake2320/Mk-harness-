# Encrypted object storage for evidence bundles and the audit-root replica
# (contract O1, S7, O9). Versioned, object-locked, replicated to the SEPARATE
# audit account so no administrator of this account can rewrite history.
resource "aws_s3_bucket" "evidence" {
  bucket              = "${local.name}-evidence-${data.aws_caller_identity.current.account_id}"
  object_lock_enabled = true
  tags                = local.tags
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode  = local.is_prod ? "COMPLIANCE" : "GOVERNANCE"
      years = local.is_prod ? 7 : null
      days  = local.is_prod ? null : 30
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "noncurrent"
    status = "Enabled"
    filter {}
    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "GLACIER_IR"
    }
  }
}

resource "aws_iam_role" "replication" {
  count              = var.audit_root_bucket_arn == "" ? 0 : 1
  name               = "${local.name}-evidence-replication"
  assume_role_policy = data.aws_iam_policy_document.s3_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "s3_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "replication" {
  count = var.audit_root_bucket_arn == "" ? 0 : 1
  role  = aws_iam_role.replication[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetReplicationConfiguration", "s3:ListBucket"], Resource = aws_s3_bucket.evidence.arn },
      { Effect = "Allow", Action = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging", "s3:GetObjectRetention", "s3:GetObjectLegalHold"], Resource = "${aws_s3_bucket.evidence.arn}/*" },
      { Effect = "Allow", Action = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags", "s3:ObjectOwnerOverrideToBucketOwner"], Resource = "${var.audit_root_bucket_arn}/*" },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.data.arn },
      { Effect = "Allow", Action = ["kms:Encrypt"], Resource = var.audit_root_kms_key_arn }
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "audit_root" {
  count      = var.audit_root_bucket_arn == "" ? 0 : 1
  depends_on = [aws_s3_bucket_versioning.evidence]
  bucket     = aws_s3_bucket.evidence.id
  role       = aws_iam_role.replication[0].arn
  rule {
    id     = "audit-root"
    status = "Enabled"
    filter {}
    delete_marker_replication {
      status = "Disabled"
    }
    destination {
      bucket        = var.audit_root_bucket_arn
      storage_class = "STANDARD"
      encryption_configuration {
        replica_kms_key_id = var.audit_root_kms_key_arn
      }
    }
    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }
  }
}
