# Providers
terraform {
  required_version = ">= 0.15"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.4.0"
    }
    crowdstrike = {
      source  = "cs-prod-cloudconnect-templates.s3.amazonaws.com/crowdstrike/crowdstrike"
      version = ">= 0.3.0"
    }
  }
}

locals {
  # Configure Account credentials and region
  account = {
    profile = "default"
    region  = "us-east-1"
  }

  # Configure your CrowdStrike Falcon API keys.  These will be used to call registration API.  Required Scope: CSPM registration Read & Write
  falcon_client_id = ""
  falcon_secret = ""
  crowdstrike_cloud = "us-1"

  # Enable Behavioral Assessment? If true, EventBridge rules will be deployed in each enabled region to forward indicators of attack (IOA) to CrowdStrike.
  enable_ioa = true

  # Optional, change to false to add CloudTrail for Read Only IOAsS
  use_existing_cloudtrail = true

  # Uncomment regions to exclude from IOA Provisioning (EventBridge Rules).  This will be useful if your organization leverages SCPs to deny specific regions.
  exclude_regions = [ 
      # "us-east-1",
      # "us-east-2",
      # "us-west-1",
      # "us-west-2",
      # "af-south-1",
      # "ap-east-1",
      # "ap-south-1",
      # "ap-south-2",
      # "ap-southeast-1",
      # "ap-southeast-2",
      # "ap-southeast-3",
      # "ap-southeast-4",
      # "ap-northeast-1",
      # "ap-northeast-2",
      # "ap-northeast-3",
      # "ca-central-1",
      # "eu-central-1",
      # "eu-west-1",
      # "eu-west-2",
      # "eu-west-3",
      # "eu-south-1",
      # "eu-south-2",
      # "eu-north-1",
      # "eu-central-2",
      # "me-south-1",
      # "me-central-1",
      # "sa-east-1"
   ]
}

provider "aws" {
  alias   = "account_1"
  region  = local.account.region
  profile = local.account.profile
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

provider "crowdstrike" {
  alias         = "falcon"
  client_id     = local.falcon_client_id
  client_secret = local.falcon_secret
}

# Register AWS account with Falcon
resource "crowdstrike_horizon_aws_account" "account" {
  cloudtrail_region           = "us-east-1"
  account_id                  = data.aws_caller_identity.current.account_id
  is_root                     = false
  is_commercial               = true
  behavior_assessment_enabled = local.enable_ioa
  sensor_management_enabled   = true
  provider                    = crowdstrike.falcon
}

locals {
    crowdstrike_account_id = 292230061137
}

# Onboard AWS Account
module "provision_1" {
  source = "../modules/provision"
  profile                 = local.account.profile
  intermediate_role       = "arn:${data.aws_partition.current.partition}:iam::${local.crowdstrike_account_id}:role/CrowdStrikeCSPMConnector"
  external_id             = crowdstrike_horizon_aws_account.account.external_id
  iam_role_arn            = crowdstrike_horizon_aws_account.account.iam_role_arn
  cs_eventbus_arn         = "arn:${data.aws_partition.current.partition}:events:us-east-1:${local.crowdstrike_account_id}:event-bus/${crowdstrike_horizon_aws_account.account.eventbus_name}"
  enable_ioa              = local.enable_ioa
  exclude_regions         = local.exclude_regions
  use_existing_cloudtrail = local.use_existing_cloudtrail
  cs_bucket_name          = crowdstrike_horizon_aws_account.account.cloudtrail_bucket

  providers = {
    aws = aws.account_1
  }
}

# Output Horizon registration response

output "registration_iam_role" {
  value = crowdstrike_horizon_aws_account.account.iam_role_arn
  description = "IAM Role ARN in your account to enable IOM"
}
output "registration_intermediate_role" {
  value = "arn:${data.aws_partition.current.partition}:iam::${local.crowdstrike_account_id}:role/CrowdStrikeCSPMConnector"
  description = "CrowdStrike IAM Role ARN in trust policy of your IAM Role to enable IOM"
}
output "registration_external_id" {
  value = crowdstrike_horizon_aws_account.account.external_id
  description = "External ID in trust policy of your IAM Role to enable IOM"
}
output "registration_cs_eventbus" {
  value = "arn:${data.aws_partition.current.partition}:events:us-east-1:${local.crowdstrike_account_id}:event-bus/${crowdstrike_horizon_aws_account.account.eventbus_name}"
  description = "CrowdStrike EventBus ARN to target from your EventBridge Rules to enable IOAs"
}
output "registration_cs_bucket_name" {
  value = crowdstrike_horizon_aws_account.account.cloudtrail_bucket
  description = "Name of CrowdStrike S3 Bucket to target from your CloudTrail to enable Read-Only IOAs (Optional)"
}
