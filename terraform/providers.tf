terraform {
  required_version = ">= 1.0"

  required_providers {
    ec = {
      source  = "elastic/ec"
      version = "0.12.4"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

provider "ec" {} # Uses EC_API_KEY from environment

provider "aws" {
  region  = var.aws_region
  profile = "company"

  default_tags {
    tags = var.aws_tags
  }
}
