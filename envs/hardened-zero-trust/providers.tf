terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Owner              = var.owner
      Environment        = var.environment
      DataClassification = var.data_classification
      ManagedBy          = "Terraform"
      Compliance         = "CIS-v3.0-NIST-800-53-CSA-CCM-v4.1"
    }
  }
}
