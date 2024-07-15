## How to Register single Account

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
This consumes the CrowdStrike Provider to register your AWS  Account with CrowdStrike Falcon

### Provision Module
This applies to each account

1. Create Read Only IAM Role to enable Indicators of Misconfiguration (IOM) Scans
    **Note**: When this is applied to the AWS Management account, then you will see all AWS Accounts in the organization populate in Falcon.
2. Create IAM Role to Allow Event Bridge rules to Put Events on CrowdStrike EventBus
3. Create EventBridge Rules in each region which target CrowdStrike EventBus to forward IOAs
4. Optional: For Org Management Account only, Create new Org-Wide CloudTrail with CrowdStrike S3 Bucket as Target to enable Read-Only IOAs