output "hardened_vpc_id" {
  value = aws_vpc.hardened_vpc.id
}

output "hardened_instance_id" {
  value = aws_instance.hardened_vm.id
}

output "kms_key_arn" {
  value = aws_kms_key.infra_cmk.arn
}
