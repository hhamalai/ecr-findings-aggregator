variable "findings_table_name" {
  type        = string
  description = "DynamoDB table name for the table used to store findings"
}

variable "vpc_id" {
  type        = string
  description = "VPC id from where to access the S3 bucket"
}

variable "s3_bucket_name" {
  type        = string
  description = "S3 bucket name"
  default     = "my-ecr-findings"
}

variable "master_account_id" {
  type = string
}

variable "account_listing_role" {
  type = string
}

variable "audit_automation_role" {
  type = string
}