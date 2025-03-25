> [!IMPORTANT]
> This repo is being deprecated  
> Please see the [Terraform Registry](https://registry.terraform.io/modules/CrowdStrike/cloud-registration/aws/latest)  
> For the latest CrowdStrike Cloud Terraform Modules  

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

2. Provide the AWS Organization ID
```
  organization_id = ""
```

3. Configure your CrowdStrike Falcon API keys.  These will be used to call registration API.  Required Scope: CSPM registration Read & Write
```
falcon_client_id = ""
falcon_secret = ""
crowdstrike_cloud = "" us-1, us-2, eu-1, us-gov-1 or us-gov-2
```

4. OPTIONAL: Custom IAM Role name for CSPM ReadOnly Role.  Leave empty to use default role name from CrowdStrike API response.
```
  custom_role_name = ""
```

5. Enable Behavioral Assessment? If true, EventBridge rules will be deployed in each enabled region to forward indicators of attack (IOA) to CrowdStrike.
```
enable_ioa = true
```

6. Optional, change to false to add CloudTrail for ReadOnly IOAs
```
use_existing_cloudtrail = true
```

7. Uncomment regions to exclude from IOA Provisioning (EventBridge Rules).  This will be useful if your organization leverages SCPs to deny specific regions.
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
    intermediate_role       = "arn:${data.aws_partition.current.partition}:iam::${local.crowdstrike_account_id}:role/${local.crowdstrike_role_name}"
    external_id             = crowdstrike_horizon_aws_account.account.external_id
    iam_role_arn            = crowdstrike_horizon_aws_account.account.iam_role_arn
    cs_eventbus_arn         = local.cs_eventbus_arn
    enable_ioa              = local.enable_ioa
    exclude_regions         = local.exclude_regions
    use_existing_cloudtrail = local.use_existing_cloudtrail
    cs_bucket_name          = crowdstrike_horizon_aws_account.account.cloudtrail_bucket
    is_gov                  = local.is_gov
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

This terraform configuration will leverage the Falcon Provider and one module:

### Falcon Provider
This consumes the CrowdStrike Provider to register your AWS Organization and Management Account with CrowdStrike Falcon

### Provision Module
This applies to each account

1. Create Read Only IAM Role to enable Indicators of Misconfiguration (IOM) Scans
    1a. When this is applied to the AWS Management account, then you will see all AWS Accounts in the organization populate in Falcon.
2. Create IAM Role to Allow Event Bridge rules to Put Events on CrowdStrike EventBus
3. Create EventBridge Rules in each region which target CrowdStrike EventBus to forward IOAs
4. Optional: For Org Management Account only, Create new Org-Wide CloudTrail with CrowdStrike S3 Bucket as Target to enable Read-Only IOAs

GovCloud Support
----------------

This solution currently supports registering GovCloud AWS to GocCloud Falcon.  
> **Note** <br> This solution does not currently support registering Commercial AWS to GovCLoud Falcon.