terraform {
  backend "s3" {
    bucket       = "secops-policy-gate-tfstate-prod"
    key          = "ec2-vpc-policy-gate/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
