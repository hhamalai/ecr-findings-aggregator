resource "aws_ecr_repository" "this" {
  name     = "ecr-cve-dashboard"
  image_scanning_configuration {
    scan_on_push = true
  }
}