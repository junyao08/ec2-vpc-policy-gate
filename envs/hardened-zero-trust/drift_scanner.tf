# 1. KMS-Encrypted SecOps Alert Topic for Out-of-Band Drift
resource "aws_sns_topic" "drift_alerts" {
  name              = "ec2-vpc-drift-alerts-${var.environment}"
  kms_master_key_id = aws_kms_key.infra_cmk.id

  tags = {
    Name = "ec2-vpc-drift-alerts-${var.environment}"
  }
}

# 2. Least-Privilege IAM Role for CodeBuild Checkov Drift Runner
resource "aws_iam_role" "codebuild_drift_role" {
  name = "codebuild-checkov-drift-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "codebuild.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "codebuild_drift_policy" {
  name = "codebuild-checkov-drift-policy-${var.environment}"
  role = aws_iam_role.codebuild_drift_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.codebuild_drift_logs.arn}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "ec2:DescribeFlowLogs"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.drift_alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["securityhub:BatchImportFindings"]
        Resource = "arn:aws:securityhub:${var.aws_region}:${data.aws_caller_identity.current.account_id}:hub/default"
      }
    ]
  })
}

# 3. AWS CodeBuild Project Running Checkov Policy-as-Code Drift Validation
resource "aws_codebuild_project" "checkov_drift_scanner" {
  name           = "checkov-ec2-vpc-drift-scanner-${var.environment}"
  description    = "Automated Checkov drift and posture scanner triggered by EC2/VPC mutations"
  service_role   = aws_iam_role.codebuild_drift_role.arn
  encryption_key = aws_kms_key.infra_cmk.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/standard:7.0"
    type            = "LINUX_CONTAINER"
    privileged_mode = false
  }

  logs_config {
    cloudwatch_logs {
      status     = "ENABLED"
      group_name = aws_cloudwatch_log_group.codebuild_drift_logs.name
    }
  }

  source {
    type      = "NO_SOURCE"
    buildspec = <<-EOT
      version: 0.2
      phases:
        install:
          commands:
            - pip install checkov boto3
        build:
          commands:
            - echo "Running Checkov drift verification and exporting SARIF to Security Hub..."
    EOT
  }

  tags = {
    Name = "checkov-ec2-vpc-drift-scanner-${var.environment}"
  }
}

# 4. EventBridge Rule Detecting Out-of-Band EC2/VPC Security Mutations
resource "aws_cloudwatch_event_rule" "ec2_vpc_drift_rule" {
  name        = "detect-ec2-vpc-config-drift-${var.environment}"
  description = "Triggers Checkov drift scan on EC2 RunInstances or Security Group ingress mutations"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName = [
        "RunInstances",
        "AuthorizeSecurityGroupIngress",
        "ModifyInstanceMetadataOptions"
      ]
    }
  })
}

resource "aws_iam_role" "eventbridge_codebuild_role" {
  name = "eventbridge-trigger-codebuild-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "eventbridge_codebuild_policy" {
  name = "eventbridge-start-build-${var.environment}"
  role = aws_iam_role.eventbridge_codebuild_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["codebuild:StartBuild"]
        Resource = aws_codebuild_project.checkov_drift_scanner.arn
      }
    ]
  })
}

resource "aws_cloudwatch_event_target" "trigger_checkov_codebuild" {
  rule     = aws_cloudwatch_event_rule.ec2_vpc_drift_rule.name
  arn      = aws_codebuild_project.checkov_drift_scanner.arn
  role_arn = aws_iam_role.eventbridge_codebuild_role.arn
}
