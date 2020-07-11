data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["lambda.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "lambda_policies" {
  statement {
    sid    = "AllowAssumeRole"
    effect = "Allow"
    resources = [
      "arn:aws:iam::${var.master_account_id}:role/${var.account_listing_role}",
      "arn:aws:iam::*:role/AuditAutomationRole"
    ]
    actions = ["sts:AssumeRole"]
  }

  statement {
    sid    = "AllowInvokingLambdas"
    effect = "Allow"
    resources = [
      aws_lambda_function.collect_findings.arn,
      aws_lambda_function.trigger_scans.arn,
      aws_lambda_function.findings_notifier.arn,
    ]
    actions = ["lambda:InvokeFunction"]
  }

  statement {
    sid    = "AllowS3"
    effect = "Allow"
    resources = [
      var.s3_bucket_arn,
      "${var.s3_bucket_arn}/*"
    ]
    actions = [
      "s3:Get*",
      "s3:List*",
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:DeleteObject",
      "s3:PutBucketPolicy",
      "s3:PutObjectVersionAcl"
    ]
  }

  statement {
    sid    = "AllowDynamoDB"
    effect = "Allow"
    resources = [
      var.dynamodb_table_arn
    ]
    actions = [
      "dynamodb:PutItem",
    ]
  }

  statement {
    sid    = "AllowAssumeRoleAuditRole"
    effect = "Allow"
    resources = [
      "arn:aws:iam::*:role/AuditAutomationRole"
    ]
    actions = [
      "sts:AssumeRole"
    ]
  }
}

resource "aws_iam_role" "this" {
  name               = "ECRScannerRole"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_policy" "this" {
  name        = "ecr_scanner_lambda_rights"
  path        = "/"
  description = "Lambda Rights for ECR Scanner"

  policy = data.aws_iam_policy_document.lambda_policies.json
}

resource "aws_iam_role_policy_attachment" "this" {
  role       = aws_iam_role.this.name
  policy_arn = aws_iam_policy.this.arn
}

data "aws_iam_policy" "aws_lambda_dynamo_execution_role" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaDynamoDBExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_dynamo" {
  role       = aws_iam_role.this.name
  policy_arn = data.aws_iam_policy.aws_lambda_dynamo_execution_role.arn
}