# ANTI-PATTERN 5: Unapproved AMI (CKV2_CUSTOM_2), oversized instance type (CKV2_CUSTOM_3),
# IMDSv1 allowed (CKV_AWS_79), unencrypted EBS volume (CKV_AWS_8), no detailed monitoring (CKV_AWS_126)
resource "aws_instance" "insecure_vm" {
  ami                    = "ami-00000000deadbeef0"
  instance_type          = "p4d.24xlarge"
  subnet_id              = aws_subnet.insecure_public_subnet.id
  vpc_security_group_ids = [aws_security_group.insecure_sg.id]

  root_block_device {
    volume_size = 50
    volume_type = "gp2"
    encrypted   = false
  }

  tags = {
    Name = "insecure-baseline-vm"
  }
}
