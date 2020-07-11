resource "aws_cloudwatch_log_group" "collect_findings" {
  name              = "/aws/lambda/${aws_lambda_function.collect_findings.function_name}"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "findings_notifier" {
  name              = "/aws/lambda/${aws_lambda_function.findings_notifier.function_name}"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "trigger_scans" {
  name              = "/aws/lambda/${aws_lambda_function.trigger_scans.function_name}"
  retention_in_days = 14
}

resource "aws_cloudwatch_event_rule" "trigger_scans" {
  name                = "trigger-container-scanning"
  description         = "Trigger the lambda to initiate ECR container scanning."
  schedule_expression = "rate(24 hours)"
}

resource "aws_cloudwatch_event_rule" "collect_findings" {
  name                = "collect-container-scanning-findings"
  description         = "Trigger the lambda to collect container vulnerability findings."
  schedule_expression = "rate(3 hours)"
}

resource "aws_cloudwatch_event_target" "trigger_scans" {
  rule = aws_cloudwatch_event_rule.trigger_scans.name
  arn  = aws_lambda_function.trigger_scans.arn
}

resource "aws_cloudwatch_event_target" "collect_findings" {
  rule = aws_cloudwatch_event_rule.collect_findings.name
  arn  = aws_lambda_function.collect_findings.arn
}
