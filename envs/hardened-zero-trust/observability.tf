resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/flow-logs/${var.environment}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.infra_cmk.arn

  tags = {
    Name = "vpc-flow-logs-${var.environment}"
  }
}

resource "aws_cloudwatch_log_group" "codebuild_drift_logs" {
  name              = "/aws/codebuild/checkov-drift-scanner-${var.environment}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.infra_cmk.arn

  tags = {
    Name = "codebuild-drift-logs-${var.environment}"
  }
}
