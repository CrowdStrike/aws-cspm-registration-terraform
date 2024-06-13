## How to Register Organizations

Configure main.tf
------------

Modify each of the following sections of the locals block to set your configuration

1. Set your AWS CLI profile name and Region for the AWS Organization Management account
```
root_account = {
    profile = "default"
    region  = "us-east-1"
}
```

2. Configure your CrowdStrike Falcon API keys.  These will be used to call registration API.  Required Scope: CSPM registration Read & Write
```
falcon_client_id = ""
falcon_secret = ""
crowdstrike_cloud = "" us-1 or us-2 or eu-1
```

3. Enable Behavioral Assessment? If true, EventBridge rules will be deployed in each enabled region to forward indicators of attack (IOA) to CrowdStrike.
```
enable_ioa = true
```

4. Optional, change to false to add CloudTrail for Read Only IOAsS
```
use_existing_cloudtrail = true
```

5. Uncomment regions to exclude from IOA Provisioning (EventBridge Rules).  This will be useful if your organization leverages SCPs to deny specific regions.
```
exclude_regions = [
    #us-east-1
    us-east-2 << This region would be excluded
```

> **Note** <br> How to provision multiple accounts:
> In main.tf duplicate the following local, provider and module blocks for each additional account you wish to provision. You will need to increment numeral values eg. account_2, provision_2, account_3, provision_3 etc

```
locals {
    account_2 = {
        profile = "profile2"
        region  = "us-east-1"
    }
}

provider "aws" {
  alias   = "account_2"
  region  = local.account_2.region
  profile = local.account_2.profile
}

module "provision_2" {
    source = "./modules/provision"
    profile           = local.account_2.profile
    intermediate_role = module.register.registration_intermediate_role
    external_id       = module.register.registration_external_id
    iam_role_arn      = module.register.registration_iam_role
    cs_eventbus_arn   = module.register.registration_cs_eventbus    
    enable_ioa        = local.enable_ioa
    exclude_regions   = local.exclude_regions
    providers = {
    aws = aws.account_2
  }
}
```

How to apply
------------
1. Initialize terraform providers and environment
```
terraform init
```
2. Generate Plan
```
terraform plan
```
3. Apply configuration
```
terraform apply
```
4. Destroy configuration **Note** This will deregister your AWS Accounts from Horizon
```
terraform destroy
```

How It Works
------------

This terraform configuration will leverage two modules: one to **register** the AWS Accounts and one to **provision** CSPM-required resources.

### register module
This only applies to the AWS Organization Management Account

1. Install falconpy python package locally in /source
2. Archive falconpy python package as zip for lambda layer
3. Archive lambda.py fucntion as zip for lambda function
4. Create AWS Secrets Manager Secret to store Falcon API Keys
5. Create IAM Role to allow Lambda basic execution and access to Secret containing Falcon API Keys
6. Create and invoke lambda function
7. Lambda function leverages the CrowdStrike Falcon API to register the AWS Account with Horizon
8. Lambda function returns API response and values to be used by provision module

### provision module
This applies to each account

1. Create Read Only IAM Role to enable Indicators of Misconfiguration (IOM) Scans
2. Create IAM Role to Allow Event Bridge rules to Put Events on CrowdStrike EventBus
3. Create EventBridge Rules in each region which target CrowdStrike EventBus to forward IOAs
4. Optional: For Org Management Account only, Create new Org-Wide CloudTrail with CrowdStrike S3 Bucket as Target to enable Read-Only IOAs