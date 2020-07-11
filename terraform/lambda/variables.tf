variable "s3_bucket_arn" {
  type = string
}

variable "s3_bucket_name" {
  type = string
}

variable "dynamodb_findings_table_name" {
  type = string
}

variable "dynamodb_table_arn" {
  type = string
}
variable "dynamodb_table_stream_arn" {
  type = string
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