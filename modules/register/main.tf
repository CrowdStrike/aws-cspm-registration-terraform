
locals {
  falcon_credentials = {
    FalconClientId = "${var.falcon_client_id}"
    FalconSecret = "${var.falcon_secret}"
  }
}

data "aws_region" "current" {}

data "aws_partition" "current" {}

# Create secret for Falcon credentials

resource "random_string" "random" {
  length = 5
  special = false
}

resource "aws_secretsmanager_secret" "falcon_credentials_secret" {
  name = "${var.resource_name}-credentials-${random_string.random.result}"
}

resource "aws_secretsmanager_secret_version" "falcon_credentials_secret_version" {
  secret_id     = aws_secretsmanager_secret.falcon_credentials_secret.id
  secret_string = jsonencode(local.falcon_credentials)
}

# Create IAM role for lambda

resource "aws_iam_role" "register_lambda_role" {
  name = "${var.resource_name}-lambda-role"
  managed_policy_arns = [
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AWSOrganizationsReadOnlyAccess"
  ]
  inline_policy {
    name = "${var.resource_name}-lambda-role-policy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action   = ["secretsmanager:GetSecretValue"]
          Effect   = "Allow"
          Resource = aws_secretsmanager_secret.falcon_credentials_secret.arn
        },
      ]
    })
  }  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
}

# Build lambda packages

resource "null_resource" "download_falconpy" {
  triggers = {
    installed = "source/layer/python"
  }
  provisioner "local-exec" {
    command = <<-EOF
      pip3 install -r requirements.txt -t source/layer/python 
    EOF
  }
}

data "archive_file" "zip_falconpy_layer" {
  depends_on = [null_resource.download_falconpy]
  type        = "zip"
  source_dir  = "source/layer"
  output_file_mode = "0666"
  output_path = "packages/layer.zip"
}

data "archive_file" "zip_register_lambda" {
  type             = "zip"
  source_file      = "source/lambda.py"
  output_file_mode = "0666"
  output_path      = "packages/lambda.py.zip"
}

# Deploy and run lambda

resource "aws_lambda_layer_version" "falconpy_lambda_layer" {
  depends_on = [data.archive_file.zip_falconpy_layer]
  filename            = "packages/layer.zip"
  layer_name          = "falconpy"
  compatible_runtimes = ["python3.10"]
}

resource "aws_lambda_function" "register_lambda" {
  depends_on = [data.archive_file.zip_register_lambda]
  filename         = "packages/lambda.py.zip"
  function_name    = "${var.resource_name}-lambda"
  role             = aws_iam_role.register_lambda_role.arn
  handler          = "lambda.lambda_handler"
  #source_code_hash = filebase64sha256("packages/lambda.py.zip")
  runtime          = "python3.10"
  timeout          = 300
  layers           = [aws_lambda_layer_version.falconpy_lambda_layer.arn]
  environment {
    variables = {
      SECRET_NAME = aws_secretsmanager_secret.falcon_credentials_secret.name
      SECRET_REGION = data.aws_region.current.name
      CS_CLOUD = var.crowdstrike_cloud
      CT_REGION = data.aws_region.current.name
      IOA = var.enable_ioa
    }
  }
}

resource "aws_lambda_invocation" "invoke_register_lambda" {
  function_name   = aws_lambda_function.register_lambda.function_name
  lifecycle_scope = "CRUD"
  input = jsonencode({
  })
}

# Output Horizon registration response

locals {
  result = jsondecode(aws_lambda_invocation.invoke_register_lambda.result)
}
output "registration_status" {
  value = local.result.status_code
}
output "registration_cid" {
  value = local.result.body.resources[0].cid
}
output "registration_iam_role" {
  value = local.result.body.resources[0].iam_role_arn
}
output "registration_intermediate_role" {
  value = local.result.body.resources[0].intermediate_role_arn
}
output "registration_external_id" {
  value = local.result.body.resources[0].external_id
}
output "registration_cs_bucket_name" {
  value = local.result.body.resources[0].aws_cloudtrail_bucket_name
}
output "registration_cs_bucket_region" {
  value = local.result.body.resources[0].aws_cloudtrail_region
}
output "registration_cs_eventbus" {
  value = local.result.body.resources[0].aws_eventbus_arn
}