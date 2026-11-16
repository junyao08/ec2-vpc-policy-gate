variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "junlab"
}

variable "owner" {
  type    = string
  default = "cloud-security-architecture"
}

variable "data_classification" {
  type    = string
  default = "Confidential"
}

variable "approved_ami_id" {
  type    = string
  default = "ami-0c55b159cbfafe1f0"
}

variable "approved_instance_type" {
  type    = string
  default = "t3.micro"
}
