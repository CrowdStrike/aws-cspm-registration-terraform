data "aws_partition" "current" {}

# Get Active Regions.
data "aws_regions" "current" {
    all_regions = true
    filter {
    name   = "opt-in-status"
    values = ["opted-in", "opt-in-not-required"]
    }
}

locals {
    available_regions = var.enable_ioa ? [for region in data.aws_regions.current.names : region] : []
    role_name = split("/", var.iam_role_arn)
}

# Data resource to be used as the assume role policy below.
data "aws_iam_policy_document" "cs-iam-assume-role-policy" {
    statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
        type = "AWS"
        identifiers = [var.intermediate_role]
    }
    condition {
        test     = "StringEquals"
        values   = [var.external_id]
        variable = "sts:ExternalId"
    }
    }
}

# Create IAM role policy giving the CrowdStrike IAM role read access to AWS resources.
resource "aws_iam_role" "cs-iam-role" {
    name               = element(local.role_name, length(local.role_name) - 1)
    assume_role_policy = data.aws_iam_policy_document.cs-iam-assume-role-policy.json
    inline_policy {
    name = "cspm_config"
    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
        {
            Action = [
            "ecr:BatchGetImage",
            "ecr:GetDownloadUrlForLayer",
            "lambda:GetLayerVersion",
            "backup:ListBackupPlans",
            "backup:ListRecoveryPointsByBackupVault",
            "ecr:GetRegistryScanningConfiguration",
            "eks:ListFargateProfiles",
            "eks:Describe*",
            "elasticfilesystem:DescribeAccessPoints",
            "lambda:GetFunction",
            "sns:GetSubscriptionAttributes"
            ]
            Effect   = "Allow"
            Resource = "*"
        }
        ]
    })
    }
}
resource "aws_iam_role_policy_attachment" "cs-iam-role-attach" {
    role       = aws_iam_role.cs-iam-role.name
    policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/SecurityAudit"
}

# Behavior

# Optional CloudTrail used for behavior assessment.
    resource "aws_cloudtrail" "crowdstrike-cloudtrail" {
      count                         = var.enable_ioa && !var.use_existing_cloudtrail ? 1 : 0
      name                          = var.organization ? "cs-horizon-org-trail" : "crowdstrike-cloudtrail"
      s3_bucket_name                = var.cs_bucket_name
      s3_key_prefix                 = ""
      include_global_service_events = true
      is_multi_region_trail         = true
      is_organization_trail         = var.organization ? true : false
      depends_on = [
        aws_iam_role.cs-iam-role
      ]
    }

data "aws_iam_policy_document" "crowdstrike-eventbridge-role-policy" {
    statement {
    effect  = "Allow"
    actions = ["events:PutEvents"]
    resources = [
        "arn:${data.aws_partition.current.partition}:events:*:*:event-bus/cs-*"
    ]
    }
}

resource "aws_iam_role" "crowdstrike-eventbridge-role" {
    count = var.enable_ioa ? 1 : 0
    name  = "CrowdStrikeCSPMEventBridge"
    assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
            Service = "events.amazonaws.com"
        }
        },
    ]
    })
    inline_policy {
    name   = "eventbridge-put-events"
    policy = data.aws_iam_policy_document.crowdstrike-eventbridge-role-policy.json
    }
}


# Create eventbus rules for each active region on the default event bus to collect CloudTrail mutation events.
# and Set rule target to CrowdStrike's eventbus.

locals {
    target_id = "CrowdStrikeCentralizeEvents"
    rule_name = "cs-cloudtrail-events-ioa-rule"
    ro_rule_name = "cs-cloudtrail-events-readonly-rule"
    eb_arn    = var.cs_eventbus_arn
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-af-south-1" {
    count    = contains(local.available_regions, "af-south-1") && !contains(var.exclude_regions, "af-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.af-south-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-af-south-1" {
    count     = contains(local.available_regions, "af-south-1") && !contains(var.exclude_regions, "af-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0 
    provider  = aws.af-south-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-af-south-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-ap-east-1" {
    count    = contains(local.available_regions, "ap-east-1") && !contains(var.exclude_regions, "ap-east-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ap-east-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ap-east-1" {
    count     = contains(local.available_regions, "ap-east-1") && !contains(var.exclude_regions, "ap-east-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ap-east-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-ap-east-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-ap-northeast-1" {
    count    = contains(local.available_regions, "ap-northeast-1") && !contains(var.exclude_regions, "ap-northeast-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ap-northeast-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ap-northeast-1" {
    count     = contains(local.available_regions, "ap-northeast-1") && !contains(var.exclude_regions, "ap-northeast-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ap-northeast-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-ap-northeast-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-ap-northeast-2" {
    count    = contains(local.available_regions, "ap-northeast-2") && !contains(var.exclude_regions, "ap-northeast-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ap-northeast-2
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ap-northeast-2" {
    count     = contains(local.available_regions, "ap-northeast-2") && !contains(var.exclude_regions, "ap-northeast-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ap-northeast-2
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-ap-northeast-2.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-ap-northeast-3" {
    count    = contains(local.available_regions, "ap-northeast-3") && !contains(var.exclude_regions, "ap-northeast-3") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ap-northeast-3
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ap-northeast-3" {
    count     = contains(local.available_regions, "ap-northeast-3") && !contains(var.exclude_regions, "ap-northeast-3") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ap-northeast-3
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-ap-northeast-3.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-ap-south-1" {
    count    = contains(local.available_regions, "ap-south-1") && !contains(var.exclude_regions, "ap-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ap-south-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ap-south-1" {
    count     = contains(local.available_regions, "ap-south-1") && !contains(var.exclude_regions, "ap-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ap-south-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-ap-south-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-ap-southeast-1" {
    count    = contains(local.available_regions, "ap-southeast-1") && !contains(var.exclude_regions, "ap-southeast-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ap-southeast-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ap-southeast-1" {
    count     = contains(local.available_regions, "ap-southeast-1") && !contains(var.exclude_regions, "ap-southeast-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ap-southeast-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-ap-southeast-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-ap-southeast-2" {
    count    = contains(local.available_regions, "ap-southeast-2") && !contains(var.exclude_regions, "ap-southeast-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ap-southeast-2
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ap-southeast-2" {
    count     = contains(local.available_regions, "ap-southeast-2") && !contains(var.exclude_regions, "ap-southeast-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ap-southeast-2
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-ap-southeast-2.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-ca-central-1" {
    count    = contains(local.available_regions, "ca-central-1") && !contains(var.exclude_regions, "ca-central-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ca-central-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ca-central-1" {
    count     = contains(local.available_regions, "ca-central-1") && !contains(var.exclude_regions, "ca-central-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ca-central-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-ca-central-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-eu-central-1" {
    count    = contains(local.available_regions, "eu-central-1") && !contains(var.exclude_regions, "eu-central-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.eu-central-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-eu-central-1" {
    count     = contains(local.available_regions, "eu-central-1") && !contains(var.exclude_regions, "eu-central-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.eu-central-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-eu-central-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-eu-north-1" {
    count    = contains(local.available_regions, "eu-north-1") && !contains(var.exclude_regions, "eu-north-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.eu-north-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-eu-north-1" {
    count     = contains(local.available_regions, "eu-north-1") && !contains(var.exclude_regions, "eu-north-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.eu-north-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-eu-north-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-eu-south-1" {
    count    = contains(local.available_regions, "eu-south-1") && !contains(var.exclude_regions, "eu-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.eu-south-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-eu-south-1" {
    count     = contains(local.available_regions, "eu-south-1") && !contains(var.exclude_regions, "eu-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.eu-south-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-eu-south-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-eu-west-1" {
    count    = contains(local.available_regions, "eu-west-1") && !contains(var.exclude_regions, "eu-west-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.eu-west-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-eu-west-1" {
    count     = contains(local.available_regions, "eu-west-1") && !contains(var.exclude_regions, "eu-west-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.eu-west-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-eu-west-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-eu-west-2" {
    count    = contains(local.available_regions, "eu-west-2") && !contains(var.exclude_regions, "eu-west-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.eu-west-2
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-eu-west-2" {
    count     = contains(local.available_regions, "eu-west-2") && !contains(var.exclude_regions, "eu-west-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.eu-west-2
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-eu-west-2.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-eu-west-3" {
    count    = contains(local.available_regions, "eu-west-3") && !contains(var.exclude_regions, "eu-west-3") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.eu-west-3
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-eu-west-3" {
    count     = contains(local.available_regions, "eu-west-3") && !contains(var.exclude_regions, "eu-west-3") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.eu-west-3
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-eu-west-3.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-me-south-1" {
    count    = contains(local.available_regions, "me-south-1") && !contains(var.exclude_regions, "me-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.me-south-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-me-south-1" {
    count     = contains(local.available_regions, "me-south-1") && !contains(var.exclude_regions, "me-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.me-south-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-me-south-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-sa-east-1" {
    count    = contains(local.available_regions, "sa-east-1") && !contains(var.exclude_regions, "sa-east-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.sa-east-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-sa-east-1" {
    count     = contains(local.available_regions, "sa-east-1") && !contains(var.exclude_regions, "sa-east-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.sa-east-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-sa-east-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-us-east-1" {
    count    = contains(local.available_regions, "us-east-1") && !contains(var.exclude_regions, "us-east-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.us-east-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-us-east-1" {
    count     = contains(local.available_regions, "us-east-1") && !contains(var.exclude_regions, "us-east-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.us-east-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-us-east-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-us-east-2" {
    count    = contains(local.available_regions, "us-east-2") && !contains(var.exclude_regions, "us-east-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.us-east-2
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-us-east-2" {
    count     = contains(local.available_regions, "us-east-2") && !contains(var.exclude_regions, "us-east-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.us-east-2
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-us-east-2.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-us-west-1" {
    count    = contains(local.available_regions, "us-west-1") && !contains(var.exclude_regions, "us-west-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.us-west-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-us-west-1" {
    count     = contains(local.available_regions, "us-west-1") && !contains(var.exclude_regions, "us-west-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.us-west-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-us-west-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-us-west-2" {
    count    = contains(local.available_regions, "us-west-2") && !contains(var.exclude_regions, "us-west-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.us-west-2
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-us-west-2" {
    count     = contains(local.available_regions, "us-west-2") && !contains(var.exclude_regions, "us-west-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.us-west-2
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-us-west-2.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

# ReadOnly Rules

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-af-south-1" {
    count    = contains(local.available_regions, "af-south-1") && !contains(var.exclude_regions, "af-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.af-south-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-af-south-1" {
    count     = contains(local.available_regions, "af-south-1") && !contains(var.exclude_regions, "af-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0 
    provider  = aws.af-south-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-af-south-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-ap-east-1" {
    count    = contains(local.available_regions, "ap-east-1") && !contains(var.exclude_regions, "ap-east-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ap-east-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-ap-east-1" {
    count     = contains(local.available_regions, "ap-east-1") && !contains(var.exclude_regions, "ap-east-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ap-east-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-ap-east-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-ap-northeast-1" {
    count    = contains(local.available_regions, "ap-northeast-1") && !contains(var.exclude_regions, "ap-northeast-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ap-northeast-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-ap-northeast-1" {
    count     = contains(local.available_regions, "ap-northeast-1") && !contains(var.exclude_regions, "ap-northeast-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ap-northeast-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-ap-northeast-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-ap-northeast-2" {
    count    = contains(local.available_regions, "ap-northeast-2") && !contains(var.exclude_regions, "ap-northeast-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ap-northeast-2
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-ap-northeast-2" {
    count     = contains(local.available_regions, "ap-northeast-2") && !contains(var.exclude_regions, "ap-northeast-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ap-northeast-2
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-ap-northeast-2.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-ap-northeast-3" {
    count    = contains(local.available_regions, "ap-northeast-3") && !contains(var.exclude_regions, "ap-northeast-3") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ap-northeast-3
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-ap-northeast-3" {
    count     = contains(local.available_regions, "ap-northeast-3") && !contains(var.exclude_regions, "ap-northeast-3") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ap-northeast-3
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-ap-northeast-3.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-ap-south-1" {
    count    = contains(local.available_regions, "ap-south-1") && !contains(var.exclude_regions, "ap-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ap-south-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-ap-south-1" {
    count     = contains(local.available_regions, "ap-south-1") && !contains(var.exclude_regions, "ap-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ap-south-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-ap-south-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-ap-southeast-1" {
    count    = contains(local.available_regions, "ap-southeast-1") && !contains(var.exclude_regions, "ap-southeast-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ap-southeast-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-ap-southeast-1" {
    count     = contains(local.available_regions, "ap-southeast-1") && !contains(var.exclude_regions, "ap-southeast-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ap-southeast-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-ap-southeast-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-ap-southeast-2" {
    count    = contains(local.available_regions, "ap-southeast-2") && !contains(var.exclude_regions, "ap-southeast-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ap-southeast-2
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-ap-southeast-2" {
    count     = contains(local.available_regions, "ap-southeast-2") && !contains(var.exclude_regions, "ap-southeast-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ap-southeast-2
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-ap-southeast-2.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-ca-central-1" {
    count    = contains(local.available_regions, "ca-central-1") && !contains(var.exclude_regions, "ca-central-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.ca-central-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-ca-central-1" {
    count     = contains(local.available_regions, "ca-central-1") && !contains(var.exclude_regions, "ca-central-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.ca-central-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-ca-central-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-eu-central-1" {
    count    = contains(local.available_regions, "eu-central-1") && !contains(var.exclude_regions, "eu-central-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.eu-central-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-eu-central-1" {
    count     = contains(local.available_regions, "eu-central-1") && !contains(var.exclude_regions, "eu-central-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.eu-central-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-eu-central-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-eu-north-1" {
    count    = contains(local.available_regions, "eu-north-1") && !contains(var.exclude_regions, "eu-north-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.eu-north-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-eu-north-1" {
    count     = contains(local.available_regions, "eu-north-1") && !contains(var.exclude_regions, "eu-north-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.eu-north-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-eu-north-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-eu-south-1" {
    count    = contains(local.available_regions, "eu-south-1") && !contains(var.exclude_regions, "eu-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.eu-south-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-eu-south-1" {
    count     = contains(local.available_regions, "eu-south-1") && !contains(var.exclude_regions, "eu-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.eu-south-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-eu-south-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-eu-west-1" {
    count    = contains(local.available_regions, "eu-west-1") && !contains(var.exclude_regions, "eu-west-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.eu-west-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-eu-west-1" {
    count     = contains(local.available_regions, "eu-west-1") && !contains(var.exclude_regions, "eu-west-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.eu-west-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-eu-west-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-eu-west-2" {
    count    = contains(local.available_regions, "eu-west-2") && !contains(var.exclude_regions, "eu-west-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.eu-west-2
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-eu-west-2" {
    count     = contains(local.available_regions, "eu-west-2") && !contains(var.exclude_regions, "eu-west-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.eu-west-2
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-eu-west-2.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-eu-west-3" {
    count    = contains(local.available_regions, "eu-west-3") && !contains(var.exclude_regions, "eu-west-3") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.eu-west-3
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-eu-west-3" {
    count     = contains(local.available_regions, "eu-west-3") && !contains(var.exclude_regions, "eu-west-3") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.eu-west-3
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-eu-west-3.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-me-south-1" {
    count    = contains(local.available_regions, "me-south-1") && !contains(var.exclude_regions, "me-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.me-south-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-me-south-1" {
    count     = contains(local.available_regions, "me-south-1") && !contains(var.exclude_regions, "me-south-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.me-south-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-me-south-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-sa-east-1" {
    count    = contains(local.available_regions, "sa-east-1") && !contains(var.exclude_regions, "sa-east-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.sa-east-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-sa-east-1" {
    count     = contains(local.available_regions, "sa-east-1") && !contains(var.exclude_regions, "sa-east-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.sa-east-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-sa-east-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-us-east-1" {
    count    = contains(local.available_regions, "us-east-1") && !contains(var.exclude_regions, "us-east-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.us-east-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-us-east-1" {
    count     = contains(local.available_regions, "us-east-1") && !contains(var.exclude_regions, "us-east-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.us-east-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-us-east-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-us-east-2" {
    count    = contains(local.available_regions, "us-east-2") && !contains(var.exclude_regions, "us-east-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.us-east-2
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-us-east-2" {
    count     = contains(local.available_regions, "us-east-2") && !contains(var.exclude_regions, "us-east-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.us-east-2
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-us-east-2.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-us-west-1" {
    count    = contains(local.available_regions, "us-west-1") && !contains(var.exclude_regions, "us-west-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.us-west-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-us-west-1" {
    count     = contains(local.available_regions, "us-west-1") && !contains(var.exclude_regions, "us-west-1") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.us-west-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-us-west-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-us-west-2" {
    count    = contains(local.available_regions, "us-west-2") && !contains(var.exclude_regions, "us-west-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider = aws.us-west-2
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-us-west-2" {
    count     = contains(local.available_regions, "us-west-2") && !contains(var.exclude_regions, "us-west-2") && var.enable_ioa && !var.is_gov ? 1 : 0
    provider  = aws.us-west-2
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-us-west-2.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

# Instantiate providers for each region

provider "aws" {
    profile                     = var.profile
    alias                       = "us-east-1"
    region                      = "us-east-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "us-east-2"
    region                      = "us-east-2"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "us-west-1"
    region                      = "us-west-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "us-west-2"
    region                      = "us-west-2"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "af-south-1"
    region                      = "af-south-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "ap-east-1"
    region                      = "ap-east-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "ap-south-1"
    region                      = "ap-south-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "ap-northeast-3"
    region                      = "ap-northeast-3"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "ap-northeast-2"
    region                      = "ap-northeast-2"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "ap-southeast-1"
    region                      = "ap-southeast-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "ap-southeast-2"
    region                      = "ap-southeast-2"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "ap-northeast-1"
    region                      = "ap-northeast-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "ca-central-1"
    region                      = "ca-central-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "eu-central-1"
    region                      = "eu-central-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "eu-west-1"
    region                      = "eu-west-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "eu-west-2"
    region                      = "eu-west-2"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "eu-south-1"
    region                      = "eu-south-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "eu-west-3"
    region                      = "eu-west-3"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "eu-north-1"
    region                      = "eu-north-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "me-south-1"
    region                      = "me-south-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "sa-east-1"
    region                      = "sa-east-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}




## GovCloud ##

provider "aws" {
    profile                     = var.profile
    alias                       = "us-gov-west-1"
    region                      = "us-gov-west-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

provider "aws" {
    profile                     = var.profile
    alias                       = "us-gov-east-1"
    region                      = "us-gov-east-1"
    skip_credentials_validation = true
    skip_requesting_account_id  = true
}

# EventBridge Rules

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-us-gov-west-1" {
    count    = contains(local.available_regions, "us-gov-west-1") && !contains(var.exclude_regions, "us-gov-west-1") && var.enable_ioa && var.is_gov ? 1 : 0
    provider = aws.us-gov-west-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-us-gov-west-1" {
    count     = contains(local.available_regions, "us-gov-west-1") && !contains(var.exclude_regions, "us-gov-west-1") && var.enable_ioa && var.is_gov ? 1 : 0 
    provider  = aws.us-gov-west-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-us-gov-west-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-us-gov-west-1" {
    count    = contains(local.available_regions, "us-gov-west-1") && !contains(var.exclude_regions, "us-gov-west-1") && var.enable_ioa && var.is_gov ? 1 : 0
    provider = aws.us-gov-west-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-us-gov-west-1" {
    count     = contains(local.available_regions, "us-gov-west-1") && !contains(var.exclude_regions, "us-gov-west-1") && var.enable_ioa && var.is_gov ? 1 : 0 
    provider  = aws.us-gov-west-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-us-gov-west-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-rule-us-gov-east-1" {
    count    = contains(local.available_regions, "us-gov-east-1") && !contains(var.exclude_regions, "us-gov-east-1") && var.enable_ioa && var.is_gov ? 1 : 0
    provider = aws.us-gov-east-1
    name     = local.rule_name
    event_pattern = jsonencode({
        source = [
            {
                "prefix": "aws."
            }
        ],
        detail-type = [
            {
                suffix = "via CloudTrail"
            }
        ],
        detail = {
            "eventName": [
                {
                    "anything-but": [
                        "InvokeExecution",
                        "Invoke",
                        "UploadPart"
                    ]
                }
            ],
            "readOnly": [
                false
            ]
        }
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-us-gov-east-1" {
    count     = contains(local.available_regions, "us-gov-east-1") && !contains(var.exclude_regions, "us-gov-east-1") && var.enable_ioa && var.is_gov ? 1 : 0 
    provider  = aws.us-gov-east-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-rule-us-gov-east-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}

resource "aws_cloudwatch_event_rule" "crowdstrike-eventbus-event-ro-rule-us-gov-east-1" {
    count    = contains(local.available_regions, "us-gov-east-1") && !contains(var.exclude_regions, "us-gov-east-1") && var.enable_ioa && var.is_gov ? 1 : 0
    provider = aws.us-gov-east-1
    name     = local.ro_rule_name
    event_pattern = jsonencode({
        source =  [
            {
            "prefix": "aws."
            }
        ],
        detail-type = [
            {
            "suffix": "via CloudTrail"
            }
        ],
        detail =  {
            "readOnly": [
                true
            ]
        },
        "$or": [
            {
                "detail": {
                    "eventName": [
                        {
                            "anything-but": [
                                "GetObject",
                                "Encrypt",
                                "Decrypt",
                                "HeadObject",
                                "ListObjects",
                                "GenerateDataKey",
                                "Sign",
                                "AssumeRole"
                            ]
                        }
                    ]
                }
            },
            {
                "detail": {
                    "eventName": [
                        "AssumeRole"
                    ],
                    "userIdentity": {
                        "type": [
                            {
                                "anything-but": [
                                    "AWSService"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    })
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}
resource "aws_cloudwatch_event_target" "crowdstrike-eventbus-event-target-ro-us-gov-east-1" {
    count     = contains(local.available_regions, "us-gov-east-1") && !contains(var.exclude_regions, "us-gov-east-1") && var.enable_ioa && var.is_gov ? 1 : 0 
    provider  = aws.us-gov-east-1
    target_id = local.target_id
    arn       = local.eb_arn
    rule      = aws_cloudwatch_event_rule.crowdstrike-eventbus-event-ro-rule-us-gov-east-1.0.name
    role_arn  = aws_iam_role.crowdstrike-eventbridge-role.0.arn
    depends_on = [
    aws_iam_role.crowdstrike-eventbridge-role
    ]
}