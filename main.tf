provider "aws" {
  version = "~> 3.0"
}

locals {
  function_name = "letsencryptlambda"
}

resource "aws_s3_bucket" "certbucket" {
  bucket = var.bucket_name
}

resource "aws_iam_policy" "lambda_iam_policy" {
  name        = "LetsEncryptLambdaPolicy"
  description = "Allows a lambda to use Route53 to pass a DNS-01 challenge and upload a cert to S3"
  policy      = <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LetsEncryptRoute53Access",
      "Effect": "Allow",
      "Action": [
        "route53:GetChange",
        "route53:ChangeResourceRecordSets",
        "route53:ListResourceRecordSets"
      ],
      "Resource": [
        "arn:aws:route53:::hostedzone/*",
        "arn:aws:route53:::change/*"
      ]
    },
    {
      "Sid": "LetsEncryptFindHostedZone",
      "Effect": "Allow",
      "Action": "route53:ListHostedZonesByName",
      "Resource": "*"
    },
    {
      "Sid": "LetsEncryptPutBucketObject",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:GetObject",
        "s3:GetObjectAcl",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::${var.bucket_name}/*"
    },
    {
      "Sid": "LambdaLogging",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*",
      "Effect": "Allow"
    }
  ]
}
JSON
}

resource "aws_iam_role" "lambda_role" {
  name               = "LetsEncryptLambdaRole"
  assume_role_policy = <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": "LambdaAssumeRole"
    }
  ]
}
JSON
}

resource "aws_iam_role_policy_attachment" "lambda_role_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_iam_policy.arn
}


resource "aws_lambda_function" "letsencryptlambda" {
  function_name = local.function_name

  filename         = "lambda_function.zip"
  role             = aws_iam_role.lambda_role.arn
  handler          = "main"
  source_code_hash = filebase64sha256("lambda_function.zip")
  runtime          = "go1.x"

  environment {
    variables = {
      BUCKET_NAME = var.bucket_name
      DOMAIN      = var.domain
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.letsencryptlambda_log_group,
  ]
}

resource "aws_cloudwatch_log_group" "letsencryptlambda_log_group" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 14
}
