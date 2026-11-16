# Passes CKV_AWS_79 (IMDSv2), CKV_AWS_8 (CMK EBS), CKV_AWS_126 (Monitoring),
# CKV_AWS_135 (EBS Optimized), CKV2_AWS_41 (IAM Role), and CKV2_CUSTOM_1..3
resource "aws_instance" "hardened_vm" {
  ami                    = var.approved_ami_id
  instance_type          = var.approved_instance_type
  subnet_id              = aws_subnet.private_workload_subnet.id
  vpc_security_group_ids = [aws_security_group.workload_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name
  monitoring             = true
  ebs_optimized          = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    encrypted             = true
    kms_key_id            = aws_kms_key.infra_cmk.arn
    delete_on_termination = true
  }

  tags = {
    Name               = "hardened-workload-vm-${var.environment}"
    Owner              = var.owner
    Environment        = var.environment
    DataClassification = var.data_classification
  }
}
