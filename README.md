> [!IMPORTANT]
> This repo is being deprecated!  
> Please see the [Terraform Registry](https://registry.terraform.io/modules/CrowdStrike/cloud-registration/aws/latest) for or the latest CrowdStrike Cloud Terraform Modules  
> and the new CrowdStrike Cloud Terraform Provider published [here](https://registry.terraform.io/providers/CrowdStrike/crowdstrike/latest).  
> Please see the [Resource Documentation](https://github.com/CrowdStrike/terraform-provider-crowdstrike/blob/main/docs/resources/cloud_aws_account.md) for detailed usage and examples.  
> This repo may still be used for examples to utilize both the legacy provider and new provider, but does not support latest CrowdStrike Cloud Terraform Modules.  It is recommended you use the latest [CrowdStrike Cloud Terraform Modules](https://registry.terraform.io/modules/CrowdStrike/cloud-registration/aws/latest).  

## Using the new CrowdStrike Cloud Terraform Provider with this repo
This directory now contains examples for both the legacy terraform provider and the new CrowdStrike Cloud Terraform Provider.
- [Register Organization - New Provider](/organization-new/README.md)  
- [Register Organization - Legacy Provider](/organization/README.md)  
- [Register Single Account - New Provider](/single-account-new/README.md)  
- [Register Single Account - Legacy Provider](/single-account/README.md)  

##
  

![](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png)

## CrowdStrike AWS Registration with Terraform

This repository provides Terraform to onboard AWS Organizations or single AWS Accounts with CrowdStrike Cloud Security.

## Use Case
- Customer declines the bash and/or terraform methods presented in the Falcon Console
- Customer needs to exclude regions prohibited by SCPs
- Customer wants to use terraform ONLY solution (terraform in console uses AWS Stacksets)

Falcon API Permissions
----------------------

Create a Falcon API Client with the following scope:
* **CSPM registration** [read]
* **CSPM registration** [write]

Requirements
------------

- Terraform: tested with v1.4.6
- Python3: tested with 3.11.3

## Questions or concerns?

If you encounter any issues or have questions about this repository, please open an [issue](https://github.com/CrowdStrike/cloud-aws-registration-terraform/issues/new/choose).

## Statement of Support

CrowdStrike AWS Registration is a community-driven, open source project designed to provide options for onboarding AWS with CrowdStrike Cloud Security. While not a formal CrowdStrike product, this repo is maintained by CrowdStrike and supported in partnership with the open source community.