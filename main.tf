provider "aws" {
  region     = "eu-west-2"
}

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 8
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  max_password_age               = 60
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 7
}

resource "aws_iam_role" "ch_role" {
  name = "CloudHealth-RO-Role"
  description = "A Read Only Role for CloudHealth to use"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::454464851268:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "c27c61c3cf1def20f2de6c5e53529e"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_policy" "ch_policy" {
  name        = "CloudHealth-RO-Policy"
  description = "A Read Only Policy for ClouldHealth to use"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "appstream:Describe*",
        "appstream:List*",
        "autoscaling:Describe*",
        "cloudformation:ListStacks",
        "cloudformation:ListStackResources",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackEvents",
        "cloudformation:DescribeStackResources",
        "cloudformation:GetTemplate",
        "cloudfront:Get*",
        "cloudfront:List*",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:ListTags",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "config:Get*",
        "config:Describe*",
        "config:Deliver*",
        "config:List*",
        "cur:Describe*",
        "dms:Describe*",
        "dms:List*",
        "dynamodb:DescribeTable",
        "dynamodb:List*",
        "ec2:Describe*",
        "ec2:GetReservedInstancesExchangeQuote",
        "ecs:List*",
        "ecs:Describe*",
        "elasticache:Describe*",
        "elasticache:ListTagsForResource",
        "elasticbeanstalk:Check*",
        "elasticbeanstalk:Describe*",
        "elasticbeanstalk:List*",
        "elasticbeanstalk:RequestEnvironmentInfo",
        "elasticbeanstalk:RetrieveEnvironmentInfo",
        "elasticfilesystem:Describe*",
        "elasticloadbalancing:Describe*",
        "elasticmapreduce:Describe*",
        "elasticmapreduce:List*",
        "es:List*",
        "es:Describe*",
        "firehose:ListDeliveryStreams",
        "firehose:DescribeDeliveryStream",
        "firehose:ListTagsForDeliveryStream",
        "iam:List*",
        "iam:Get*",
        "iam:GenerateCredentialReport",
        "kinesis:Describe*",
        "kinesis:List*",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:ListKeys",
        "kms:ListResourceTags",
        "lambda:List*",
        "logs:Describe*",
        "logs:ListTagsLogGroup",
        "organizations:ListAccounts",
        "organizations:ListTagsForResource",
        "organizations:DescribeOrganization",
        "redshift:Describe*",
        "route53:Get*",
        "route53:List*",
        "rds:Describe*",
        "rds:ListTagsForResource",
        "s3:GetBucketAcl",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetBucketWebsite",
        "s3:List*",
        "sagemaker:Describe*",
        "sagemaker:List*",
        "savingsplans:DescribeSavingsPlans",
        "sdb:GetAttributes",
        "sdb:List*",
        "ses:Get*",
        "ses:List*",
        "sns:Get*",
        "sns:List*",
        "sqs:GetQueueAttributes",
        "sqs:ListQueues",
        "storagegateway:List*",
        "storagegateway:Describe*",
        "workspaces:Describe*",
        "eks:Describe*",
        "eks:List*",
        "fsx:Describe*"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "policy-attach" {
  role       = aws_iam_role.ch_role.name
  policy_arn = aws_iam_policy.ch_policy.arn
}

resource "aws_iam_user" "sl_user" {
  name = "em7"
}

resource "aws_iam_group" "sl_group" {
  name = "CDW-EM7-Group"
}

resource "aws_iam_policy" "sl_policy" {
  name        = "ScienceLogicDynamicApplicationPolicy"
  description = "A policy for the em7 IAM user for CDW monitoring"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "waf:ListWebACLs",
                "waf-regional:GetRuleGroup",
                "ec2:DescribeInstances",
                "cloudtrail:GetTrailStatus",
                "waf-regional:GetRateBasedRule",
                "ec2:DescribeSnapshots",
                "ecs:DescribeTaskDefinition",
                "elasticbeanstalk:DescribeEnvironmentResources",
                "elasticmapreduce:ListInstances",
                "elasticbeanstalk:DescribeEnvironments",
                "cloudfront:GetStreamingDistribution",
                "waf-regional:GetWebACL",
                "ec2:DescribeVolumes",
                "waf:GetRuleGroup",
                "waf:GetWebACL",
                "waf-regional:ListWebACLs",
                "lambda:ListFunctions",
                "s3:GetBucketWebsite",
                "lightsail:GetInstances",
                "lambda:ListAliases",
                "cloudwatch:GetMetricStatistics",
                "cloudtrail:DescribeTrails",
                "directconnect:DescribeConnections",
                "cloudfront:ListInvalidations",
                "cloudwatch:DescribeAlarms",
                "ecs:ListContainerInstances",
                "ec2:DescribeSubnets",
                "glacier:ListVaults",
                "autoscaling:DescribeAutoScalingInstances",
                "s3:GetBucketTagging",
                "dynamodb:ListTables",
                "ec2:DescribeRegions",
                "sns:ListTopics",
                "s3:ListBucket",
                "shield:ListAttacks",
                "cloudwatch:ListMetrics",
                "ecs:ListServices",
                "cloudwatch:DescribeAlarmHistory",
                "storagegateway:ListGateways",
                "waf-regional:ListResourcesForWebACL",
                "lambda:ListTags",
                "ec2:DescribeAvailabilityZones",
                "ecs:ListTasks",
                "lightsail:GetRegions",
                "rds:DescribeDBInstances",
                "redshift:DescribeLoggingStatus",
                "ecs:DescribeTasks",
                "route53:ListHostedZones",
                "sns:ListSubscriptions",
                "ec2:DescribeSecurityGroups",
                "route53:ListHealthChecks",
                "rds:ListTagsForResource",
                "s3:ListAllMyBuckets",
                "ec2:DescribeVpcs",
                "shield:ListProtections",
                "elasticloadbalancing:DescribeTargetGroups",
                "cloudfront:ListStreamingDistributions",
                "iam:GetUser",
                "opsworks:DescribeStacks",
                "route53:GetHostedZone",
                "cloudfront:GetDistribution",
                "elasticloadbalancing:DescribeLoadBalancers",
                "dynamodb:DescribeTable",
                "autoscaling:DescribeAutoScalingGroups",
                "route53:ListResourceRecordSets",
                "shield:DescribeEmergencyContactSettings",
                "apigateway:GET",
                "waf:GetRule",
                "ec2:DescribeRouteTables",
                "waf:GetRateBasedRule",
                "shield:GetSubscriptionState",
                "directconnect:DescribeTags",
                "glacier:ListTagsForVault",
                "ec2:DescribeVpnConnections",
                "ec2:DescribeVpcPeeringConnections",
                "sqs:GetQueueAttributes",
                "ecs:DescribeClusters",
                "s3:GetObject",
                "opsworks:DescribeInstances",
                "lambda:ListEventSourceMappings",
                "elasticache:DescribeCacheClusters",
                "ec2:DescribeVpnGateways",
                "cloudwatch:GetMetricData",
                "rds:DescribeDBSubnetGroups",
                "s3:GetBucketLogging",
                "autoscaling:DescribeLaunchConfigurations",
                "lambda:GetAccountSettings",
                "waf-regional:GetRule",
                "glacier:GetVaultNotifications",
                "directconnect:DescribeVirtualInterfaces",
                "elasticloadbalancing:DescribeListeners",
                "elasticmapreduce:ListClusters",
                "ecs:DescribeServices",
                "lightsail:GetInstanceMetricData",
                "lightsail:GetBundles",
                "ecs:DescribeContainerInstances",
                "elasticfilesystem:DescribeFileSystems",
                "ecs:ListClusters",
                "sqs:ListQueues",
                "elasticloadbalancing:DescribeTags",
                "ec2:DescribeNatGateways",
                "elasticbeanstalk:DescribeConfigurationSettings",
                "storagegateway:ListVolumes",
                "cloudfront:ListDistributions",
                "elasticloadbalancing:DescribeTargetHealth",
                "redshift:DescribeClusters",
                "s3:GetBucketLocation",
                "lambda:GetPolicy"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_policy_attachment" "policy-attach" {
  name       = "test-attachment"
  groups     = [aws_iam_group.sl_group.name]
  policy_arn = aws_iam_policy.sl_policy.arn
}

resource "aws_iam_user_group_membership" "add-user" {
  user = aws_iam_user.sl_user.name

  groups = [
    aws_iam_group.sl_group.name,
  ]
}

# Creates the Admins role with trusts to the CDW Identity account
data "aws_iam_policy" "admin_policy" {
  name = "AdministratorAccess"
}
resource "aws_iam_role" "admin_role" {
  name = "CDW-CustomerAdmins"
  assume_role_policy = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::759615242590:root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {}
        }
    ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "attach_admin" {
  role       = aws_iam_role.admin_role.name
  policy_arn = data.aws_iam_policy.admin_policy.arn
}

# Creates the Network Admins role with trusts to the CDW Identity account
data "aws_iam_policy" "networkadmin_policy" {
  name = "NetworkAdministrator"
}
resource "aws_iam_role" "networkadmin_role" {
  name = "CDW-CustomerNetworkAdmins"
  assume_role_policy = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::759615242590:root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {}
        }
    ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "attach_networkadmin" {
  role       = aws_iam_role.networkadmin_role.name
  policy_arn = data.aws_iam_policy.networkadmin_policy.arn
}

# Creates the Read Only role with trusts to the CDW Identity account
data "aws_iam_policy" "readonly_policy" {
  name = "ReadOnlyAccess"
}
resource "aws_iam_role" "readonly_role" {
  name = "CDW-CustomerReadOnly"
  assume_role_policy = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::759615242590:root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {}
        }
    ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "attach_readonly" {
  role       = aws_iam_role.readonly_role.name
  policy_arn = data.aws_iam_policy.readonly_policy.arn
}

# Creates the Second Line role with trusts to the CDW Identity account
data "aws_iam_policy" "secondline_policy" {
  name = "SupportUser"
}
resource "aws_iam_role" "secondline_role" {
  name = "CDW-CustomerSecondLine"
  assume_role_policy = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::759615242590:root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {}
        }
    ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "attach_secondline" {
  role       = aws_iam_role.secondline_role.name
  policy_arn = data.aws_iam_policy.secondline_policy.arn
}
