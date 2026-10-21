# Who may talk to whom. The kernel API is never reachable from the public
# internet except for /webhooks/* through the ALB (ingress.tf); /internal/*
# is only reachable from the application tasks.
resource "aws_security_group" "alb" {
  name   = "${local.name}-alb"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }
  tags = local.tags
}

resource "aws_security_group" "app" {
  name   = "${local.name}-app"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

resource "aws_security_group" "kernel_api" {
  name   = "${local.name}-kernel-api"
  vpc_id = aws_vpc.this.id
  # /internal/v1 from the application only; /webhooks from the ALB only.
  ingress {
    from_port       = 8090
    to_port         = 8090
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id, aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }
  tags = local.tags
}

resource "aws_security_group" "kernel_worker" {
  name   = "${local.name}-kernel-worker"
  vpc_id = aws_vpc.this.id
  # Metrics scrape from the collector only.
  ingress {
    from_port       = 9100
    to_port         = 9100
    protocol        = "tcp"
    security_groups = [aws_security_group.collector.id]
  }
  # Provider egress (api.twilio.com) via NAT; the application-level egress
  # allowlist (MK_EGRESS_AUTHORITIES) is the authoritative control.
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [for s in aws_subnet.data : s.cidr_block]
  }
  egress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [for s in aws_subnet.data : s.cidr_block]
  }
  tags = local.tags
}

resource "aws_security_group" "collector" {
  name   = "${local.name}-collector"
  vpc_id = aws_vpc.this.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

resource "aws_security_group" "db" {
  name   = "${local.name}-db"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id, aws_security_group.kernel_api.id, aws_security_group.kernel_worker.id]
  }
  tags = local.tags
}

resource "aws_security_group" "redis" {
  name   = "${local.name}-redis"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.kernel_api.id, aws_security_group.kernel_worker.id]
  }
  tags = local.tags
}
