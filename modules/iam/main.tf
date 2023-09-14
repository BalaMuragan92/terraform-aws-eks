##############
# IAM account
##############
locals {
  name   = "ex-${basename(path.cwd)}"
  region = "ap-southeast-3"

  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)

  tags = {
    Example    = local.name
    GithubRepo = "terraform-aws-alb"
    GithubOrg  = "terraform-aws-modules"
  }
}

provider "aws" {
  region = local.region
  # Make it faster by skipping something
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_credentials_validation = true
  skip_requesting_account_id  = true
}
module "allow_eks_admin_access_iam_policy" {
  source = "../../../../"
  create_policy = true

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Action = [
          "eks:*",
        ]
        Effect   = "Allow"
        Resource = module.eks.cluster_arn
      },
    ]
  })
}
