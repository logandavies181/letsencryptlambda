provider "aws" {
  version = "~> 3.0"
}

resource "aws_s3_bucket" "certbucket" {
  bucket = var.bucket_name
}

resource "aws_iam_policy" "lambda_iam_policy" {
  name = "LetsEncryptLambdaPolicy"
  description = "Allows a lambda to use Route53 to pass a DNS-01 challenge and upload a cert to S3"
  policy = <<JSON
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
       }
   ]
}
JSON
}
