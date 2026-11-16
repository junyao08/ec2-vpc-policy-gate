# ANTI-PATTERN 1: VPC with no Flow Logs enabled (violates CKV2_AWS_11 / CIS 3.7)
# ANTI-PATTERN 2: Missing mandatory governance tags (violates CKV2_CUSTOM_1)
resource "aws_vpc" "insecure_vpc" {
  cidr_block = "10.99.0.0/16"

  tags = {
    Name = "insecure-baseline-vpc"
  }
}

# ANTI-PATTERN 3: Auto-assigns public IPv4 on launch (violates CKV_AWS_130)
resource "aws_subnet" "insecure_public_subnet" {
  vpc_id                  = aws_vpc.insecure_vpc.id
  cidr_block              = "10.99.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "insecure-public-subnet"
  }
}

# ANTI-PATTERN 4: Unrestricted 0.0.0.0/0 SSH & RDP ingress + missing rule descriptions
# Violates CKV_AWS_24, CKV_AWS_25, CKV_AWS_23, CIS 5.1, CIS 5.2
resource "aws_security_group" "insecure_sg" {
  name   = "insecure-open-sg"
  vpc_id = aws_vpc.insecure_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
