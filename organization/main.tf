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
  # Configure AWS Organization Management Account credentials and region
  root_account = {
    profile = "default"
    region  = "us-east-1"
  }

  # Provide your AWS organization ID.  Eg. o-1qaz2wsx
  organization_id = ""

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
  region  = local.root_account.region
  profile = local.root_account.profile
}

data "aws_caller_identity" "current" {}

provider "crowdstrike" {
  alias         = "falcon"
  client_id     = local.falcon_client_id
  client_secret = local.falcon_secret
}

# Register AWS Organization with Falcon
resource "crowdstrike_horizon_aws_account" "account" {
  cloudtrail_region           = "us-east-1"
  account_id                  = data.aws_caller_identity.current.account_id
  organization_id             = local.organization_id
  is_root                     = true
  is_commercial               = true
  behavior_assessment_enabled = local.enable_ioa
  sensor_management_enabled   = true
  use_existing_cloudtrail     = local.use_existing_cloudtrail
  provider                    = crowdstrike.falcon
}

locals {
    crowdstrike_account_id = 292230061137
}

module "provision_1" {
    source = "../modules/provision"
    profile                 = local.root_account.profile
    intermediate_role       = "arn:aws:iam::${local.crowdstrike_account_id}:role/CrowdStrikeCSPMConnector"
    external_id             = crowdstrike_horizon_aws_account.account.external_id
    iam_role_arn            = crowdstrike_horizon_aws_account.account.iam_role_arn
    cs_eventbus_arn         = "arn:aws:events:us-east-1:${local.crowdstrike_account_id}:event-bus/${crowdstrike_horizon_aws_account.account.eventbus_name}"
    enable_ioa              = local.enable_ioa
    exclude_regions         = local.exclude_regions
    use_existing_cloudtrail = local.use_existing_cloudtrail
    cs_bucket_name          = crowdstrike_horizon_aws_account.account.cloudtrail_bucket

    providers = {
    aws = aws.account_1
  }
}

# Duplicate the following local, provider and module blocks to provision additional accounts
# You will need to increment numeral values eg. account_2, provision_2, account_3, provision_3 etc

# locals {
#     account_2 = {
#         profile = "profile2"
#         region  = "us-east-1"
#     }
# }

# provider "aws" {
#   alias   = "account_2"
#   region  = local.account_2.region
#   profile = local.account_2.profile
# }

# module "provision_2" {
#     source = "../modules/provision"
#     profile           = local.account_2.profile
#     intermediate_role       = "arn:aws:iam::${local.crowdstrike_account_id}:role/CrowdStrikeCSPMConnector"
#     external_id             = crowdstrike_horizon_aws_account.account.external_id
#     iam_role_arn            = crowdstrike_horizon_aws_account.account.iam_role_arn
#     cs_eventbus_arn         = "arn:aws:events:us-east-1:${local.crowdstrike_account_id}:event-bus/${crowdstrike_horizon_aws_account.account.eventbus_name}"
#     enable_ioa              = local.enable_ioa
#     exclude_regions         = local.exclude_regions
#     use_existing_cloudtrail = local.use_existing_cloudtrail
#     cs_bucket_name          = crowdstrike_horizon_aws_account.account.cloudtrail_bucket
#     providers = {
#     aws = aws.account_2
#   }
# }