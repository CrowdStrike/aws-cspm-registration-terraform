locals {
    # Configure Root Account credentials and region
    root_account = {
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

terraform {
    required_providers {
        aws = {
            source  = "hashicorp/aws"
            version = "5.4.0"
        }
    }
}

provider "aws" {
  alias   = "account_1"
  region  = local.root_account.region
  profile = local.root_account.profile
}

module "register" {
    source = "./modules/register"
    falcon_client_id  = local.falcon_client_id
    falcon_secret     = local.falcon_secret
    crowdstrike_cloud = local.crowdstrike_cloud
    enable_ioa        = local.enable_ioa
    providers = {
    aws = aws.account_1
  }
}

module "provision_1" {
    source = "./modules/provision"
    profile                 = local.root_account.profile
    intermediate_role       = module.register.registration_intermediate_role
    external_id             = module.register.registration_external_id
    iam_role_arn            = module.register.registration_iam_role
    cs_eventbus_arn         = module.register.registration_cs_eventbus
    enable_ioa              = local.enable_ioa
    exclude_regions         = local.exclude_regions
    use_existing_cloudtrail = local.use_existing_cloudtrail
    cs_bucket_name          = module.register.registration_cs_bucket_name

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
#     source = "./modules/provision"
#     profile           = local.account_2.profile
#     intermediate_role = module.register.registration_intermediate_role
#     external_id       = module.register.registration_external_id
#     iam_role_arn      = module.register.registration_iam_role
#     cs_eventbus_arn   = module.register.registration_cs_eventbus    
#     enable_ioa        = local.enable_ioa
#     exclude_regions   = local.exclude_regions
#     providers = {
#     aws = aws.account_2
#   }
# }