module "vpc" {
    source = "../../"
    name = local.name
    cidr = local.vpc_cidr

    azs             = ["ap-southeast-3a", "ap-southeast-3b"]
    private_subnets = ["10.0.0.0/19", "10.0.32.0/19"]
    public_subnets  = ["10.0.64.0/19", "10.0.96.0/19"]
    database_subnets = ["10.0.128.0/19", "10.0.160.0/19"]
    public_subnet_tags = {
        "kubernetes.io/role/elb" = "1"
    }
    private_subnet_tags = {
        "kubernetes.io/role/internal-elb" = "1"
    }

    enable_nat_gateway     = true
    single_nat_gateway     = true
    one_nat_gateway_per_az = false

    create_database_subnet_group           = true
    create_database_subnet_route_table     = true
    create_database_internet_gateway_route = true

    enable_dns_hostnames = true
    enable_dns_support   = true
}

locals {
  name   = "ex-${basename(path.cwd)}"
  region = "ap-southeast-3"

  vpc_cidr = "10.0.0.0/16"
  azs             = ["ap-southeast-3a", "ap-southeast-3b"]
  tags = {
    Example    = local.name
    GithubRepo = "terraform-aws-alb"
    GithubOrg  = "terraform-aws-modules"
  }
}