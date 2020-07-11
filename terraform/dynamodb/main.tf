resource "aws_dynamodb_table" "image_vulnerabilities" {
  name             = var.findings_table_name
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "sha_digest"
  range_key        = "tag"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "sha_digest"
    type = "S"
  }

  attribute {
    name = "tag"
    type = "S"
  }
}

output "dynamodb_table_arn" {
  value = aws_dynamodb_table.docker_images_vulnerabilities.arn
}

output "dynamodb_table_stream_arn" {
  value = aws_dynamodb_table.docker_images_vulnerabilities.stream_arn
}
