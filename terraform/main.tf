provider "aws" {
  region              = "eu-west-1"
  allowed_account_ids = ["00000000000"]
}

terraform {
  backend "s3" {
    bucket         = "bucket-name"
    key            = "ecr-scan-findings-aggregator.tfstate"
    region         = "eu-west-1"
    dynamodb_table = "dynamodb-table"
  }
}

module "ecr" {
  source = "./ecr"
}

module "s3" {
  source          = "./s3"
  lambda_role_arn = module.lambda.lambda_role_arn
  s3_bucket_name = var.s3_bucket_name
  vpc_id = var.vpc_id
}

module "lambda" {
  source                        = "./lambda"
  s3_bucket_arn                 = module.s3.s3_bucket_arn
  s3_bucket_name                = var.s3_bucket_name
  dynamodb_table_arn            = module.dynamodb.dynamodb_table_arn
  dynamodb_table_stream_arn     = module.dynamodb.dynamodb_table_stream_arn
  dynamodb_findings_table_name  = var.findings_table_name
  account_listing_role = var.account_listing_role
  audit_automation_role = var.audit_automation_role
  master_account_id = var.master_account_id
}

module "dynamodb" {
  source = "./dynamodb"
  findings_table_name = var.findings_table_name
}
