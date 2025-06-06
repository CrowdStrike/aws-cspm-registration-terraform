# Providers
terraform {
  required_version = ">= 0.15"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.4.0"
    }
    crowdstrike = {
      source  = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

##############################################
### Modify locals for custom configuration ###
##############################################

locals {
  # Configure Account credentials and region where profile = current AWS CLI profile
  account = {
    profile = "default"
    region  = "us-east-1"
  }

  # Configure your CrowdStrike Falcon API keys.  These will be used to call registration API.  Required Scope: CSPM registration Read & Write
  falcon_client_id = ""
  falcon_secret = ""
  crowdstrike_cloud = "" # valid values inlcude: us-1, us-2, eu-1, us-gov-1, us-gov-2

  # Custom IAM Role name for CSPM ReadOnly Role.  Leave empty to use default role name from CrowdStrike API response.
  custom_role_name = ""

  # Enable Behavioral Assessment? If true, EventBridge rules will be deployed in each enabled region to forward indicators of attack (IOA) to CrowdStrike.
  enable_ioa = true

  # Optional, change to false to add CloudTrail for ReadOnly IOAs
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

################################
### End custom configuration ###
################################

provider "aws" {
  alias   = "account_1"
  region  = local.account.region
  profile = local.account.profile
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

provider "crowdstrike" {
  alias         = "falcon"
  client_id     = local.falcon_client_id
  client_secret = local.falcon_secret
  cloud         = local.crowdstrike_cloud
}

locals {
    is_merlin              = local.crowdstrike_cloud == "us-gov-2" ? true : false
    is_gov                 = strcontains(local.crowdstrike_cloud, "gov")
    api_url                = (local.is_gov) ? (local.is_merlin ? "https://api.us-gov-2.crowdstrike.mil" : "https://api.laggar.gcw.crowdstrike.com") : "https://api.crowdstrike.com"
    crowdstrike_role_name  = local.is_gov ? "CrowdstrikeCSPMConnector" : "CrowdStrikeCSPMConnector"
    crowdstrike_account_id = (local.is_gov) ? (local.is_merlin ? "142028973013" : "358431324613") : "292230061137"
    cs_eventbus_arn        = (local.is_gov) ? split(",", crowdstrike_cloud_aws_account.account.eventbus_name)[0] : "arn:${data.aws_partition.current.partition}:events:us-east-1:${local.crowdstrike_account_id}:event-bus/${crowdstrike_cloud_aws_account.account.eventbus_name}"
    iam_role_arn           = local.custom_role_name != "" ? format("arn:%s:iam::%s:role/%s", data.aws_partition.current.partition, data.aws_caller_identity.current.account_id, local.custom_role_name) : local.custom_role_name
}

# Register AWS account with Falcon
resource "crowdstrike_cloud_aws_account" "account" {
  account_id      = data.aws_caller_identity.current.account_id
  account_type    = local.is_gov ? "gov" : "commercial"

  asset_inventory = {
    enabled = true
    role_name = local.custom_role_name
  }
  realtime_visibility = {
    enabled           = local.enable_ioa
    cloudtrail_region = local.account.region
  }
  dspm = {
    enabled = false
  }
  idp = {
    enabled = true
  }
  sensor_management = {
    enabled = true
  }

  provider = crowdstrike.falcon
}

# Onboard AWS Account

module "provision_1" {
  source = "../modules/provision"
  profile                 = local.account.profile
  intermediate_role       = "arn:${data.aws_partition.current.partition}:iam::${local.crowdstrike_account_id}:role/${local.crowdstrike_role_name}"
  external_id             = crowdstrike_cloud_aws_account.account.external_id
  iam_role_arn            = crowdstrike_cloud_aws_account.account.iam_role_arn
  cs_eventbus_arn         = local.cs_eventbus_arn
  enable_ioa              = local.enable_ioa
  exclude_regions         = local.exclude_regions
  use_existing_cloudtrail = local.use_existing_cloudtrail
  cs_bucket_name          = crowdstrike_cloud_aws_account.account.cloudtrail_bucket_name
  is_gov                  = local.is_gov

  providers = {
    aws = aws.account_1
  }
}

# Output CrowdStrike registration response

output "registration_iam_role" {
  value = crowdstrike_cloud_aws_account.account.iam_role_arn
  description = "IAM Role ARN in your account to enable IOM"
}
output "registration_intermediate_role" {
  value = "arn:${data.aws_partition.current.partition}:iam::${local.crowdstrike_account_id}:role/${local.crowdstrike_role_name}"
  description = "CrowdStrike IAM Role ARN in trust policy of your IAM Role to enable IOM"
}
output "registration_external_id" {
  value = crowdstrike_cloud_aws_account.account.external_id
  description = "External ID in trust policy of your IAM Role to enable IOM"
}
output "registration_cs_eventbus" {
  value = local.cs_eventbus_arn
  description = "CrowdStrike EventBus ARN to target from your EventBridge Rules to enable IOAs"
}
output "registration_cs_bucket_name" {
  value = crowdstrike_cloud_aws_account.account.cloudtrail_bucket_name
  description = "Name of CrowdStrike S3 Bucket to target from your CloudTrail to enable Read-Only IOAs (Optional)"
}
