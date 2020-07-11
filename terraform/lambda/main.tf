data "archive_file" "collect_findings_zip" {
  type        = "zip"
  source_file = "${path.module}/files/collect-findings/collect-findings"
  output_path = "collect_findings.zip"
}

resource "aws_lambda_function" "collect_findings" {
  filename         = "collect_findings.zip"
  function_name    = "collect-findings"
  role             = aws_iam_role.this.arn
  handler          = "collect-findings"
  timeout          = 300
  source_code_hash = data.archive_file.collect_findings_zip.output_base64sha256
  runtime          = "go1.x"
  environment {
    variables = {
      DYNAMODB_TABLE = var.dynamodb_findings_table_name
      S3_BUCKET = var.s3_bucket_name
      AUDIT_AUTOMATION_ROLE = var.audit_automation_role
      ACCOUNT_LISTING_ROLE = var.account_listing_role
      MASTER_ACCOUNT_ID = var.master_account_id
    }
  }
}

resource "aws_lambda_permission" "collect_findings" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.collect_findings.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.collect_findings.arn
}


data "archive_file" "trigger_scans_zip" {
  type        = "zip"
  source_file = "${path.module}/files/trigger-scans/trigger-scans"
  output_path = "trigger_scans.zip"
}

resource "aws_lambda_function" "trigger_scans" {
  filename         = "trigger_scans.zip"
  function_name    = "trigger-scans"
  role             = aws_iam_role.this.arn
  handler          = "trigger-scans"
  timeout          = 300
  source_code_hash = data.archive_file.trigger_scans_zip.output_base64sha256
  runtime          = "go1.x"
  environment {
    variables = {
      AUDIT_AUTOMATION_ROLE = var.audit_automation_role
      ACCOUNT_LISTING_ROLE = var.account_listing_role
      MASTER_ACCOUNT_ID = var.master_account_id
    }
  }
}

resource "aws_lambda_permission" "trigger_scans" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.trigger_scans.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.trigger_scans.arn
}

data "archive_file" "findings_notifier_zip" {
  type        = "zip"
  source_file = "${path.module}/files/findings-notifier/findings-notifier"
  output_path = "findings_notifier.zip"
}

resource "aws_lambda_function" "findings_notifier" {
  filename         = "findings_notifier.zip"
  function_name    = "findings-notifier"
  role             = aws_iam_role.this.arn
  handler          = "findings-notifier"
  timeout          = 60
  source_code_hash = data.archive_file.findings_notifier_zip.output_base64sha256
  runtime          = "go1.x"
  environment {
    variables = {
      BotUrl = "<YOUR_HUBOT_ALERT_URL>"
    }
  }
}

resource "aws_lambda_event_source_mapping" "dynamo_db_stream_trigger" {
  event_source_arn  = var.dynamodb_table_stream_arn
  function_name     = aws_lambda_function.findings_notifier.arn
  starting_position = "LATEST"
}

output "lambda_role_arn" {
  value = aws_iam_role.this.arn
}
