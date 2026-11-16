resource "aws_vpc" "hardened_vpc" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name               = "hardened-zero-trust-vpc-${var.environment}"
    Owner              = var.owner
    Environment        = var.environment
    DataClassification = var.data_classification
  }
}

# CIS 5.4 / CKV2_AWS_12: Lock down Default Security Group (zero ingress/egress rules)
resource "aws_default_security_group" "default_lockdown" {
  vpc_id = aws_vpc.hardened_vpc.id

  tags = {
    Name = "default-sg-locked-${var.environment}"
  }
}

# CIS 3.7 / CKV2_AWS_11: Enable KMS-encrypted VPC Flow Logs for ALL traffic
resource "aws_flow_log" "vpc_flow_log" {
  iam_role_arn    = aws_iam_role.vpc_flow_logs_role.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.hardened_vpc.id

  tags = {
    Name = "hardened-vpc-flow-log-${var.environment}"
  }
}

# CKV_AWS_130: Private workload subnet with auto-public IP disabled
resource "aws_subnet" "private_workload_subnet" {
  vpc_id                  = aws_vpc.hardened_vpc.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false

  tags = {
    Name = "private-workload-subnet-${var.environment}"
  }
}

# CKV_AWS_23 / CKV_AWS_24 / CKV_AWS_25 / CKV_AWS_382: Scoped SG with descriptions & restricted egress
resource "aws_security_group" "workload_sg" {
  name        = "hardened-workload-sg-${var.environment}"
  description = "Zero-trust workload security group allowing internal VPC HTTPS only"
  vpc_id      = aws_vpc.hardened_vpc.id

  ingress {
    description = "Allow HTTPS traffic strictly from internal VPC CIDR"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.hardened_vpc.cidr_block]
  }

  egress {
    description = "Allow HTTPS egress to AWS PrivateLink VPC endpoints within VPC CIDR"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.hardened_vpc.cidr_block]
  }

  tags = {
    Name = "hardened-workload-sg-${var.environment}"
  }
}
