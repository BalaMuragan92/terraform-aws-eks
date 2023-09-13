##################################################################
# Application Load Balancer
##################################################################
provider "aws" {
  region = local.region
  # Make it faster by skipping something
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_credentials_validation = true
  skip_requesting_account_id  = true
}

data "aws_availability_zones" "available" {}

module "alb" {
    source = "../../"
    vpc_id  = module.vpc.vpc_id
    subnets = module.vpc.public_subnets

    # Attach security groups
    security_groups = [module.vpc.default_security_group_id]
    # Attach rules to the created security group
    security_group_rules = {
        ingress_all_http = {
        type        = "ingress"
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"
        description = "HTTP web traffic"
        cidr_blocks = ["0.0.0.0/0"]
        },
        ingress_all_https = {
        type        = "ingress"
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        description = "HTTPS web traffic"
        cidr_blocks = ["0.0.0.0/0"]
        },
        egress_all = {
        type        = "egress"
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
        }
    }

    target_groups = [
        {
        name_prefix      = "tggrp-"
        backend_protocol = "HTTP"
        backend_port     = 30080
        target_type      = "instance"
        health_check = {
            enabled             = true
            interval            = 30
            path                = "/"
            port                = "traffic-port"
            healthy_threshold   = 3
            unhealthy_threshold = 3
            timeout             = 6
            protocol            = "HTTP"
            matcher             = "200-399"
        }
        }
    ]

    https_listeners = [
        {
        port               = 443
        protocol           = "HTTPS"
        target_group_index = 0
            certificate_arn    = "arn:aws:acm:ap-southeast-3:891347655196:certificate/626ba94e-91d7-48d0-8926-251c14afc8b6"
        }
    ]

    http_tcp_listeners = [
        {
        port        = 80
        protocol    = "HTTP"
        action_type = "redirect"
        redirect = {
            port        = "443"
            protocol    = "HTTPS"
            status_code = "HTTP_301"
        }
        }
    ]

}
module "vpc" {
  source = "../vpc"
}

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
