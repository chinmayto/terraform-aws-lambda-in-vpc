################################################################################
# Create VPC and components
################################################################################

module "vpc" {
  source               = "./modules/vpc"
  name                 = "My-VPC"
  aws_region           = var.aws_region
  vpc_cidr_block       = var.vpc_cidr_block
  enable_dns_hostnames = var.enable_dns_hostnames
  aws_azs              = var.aws_azs
  common_tags          = local.common_tags
  naming_prefix        = local.naming_prefix
}


################################################################################
# Creating DynamoDB table
################################################################################
resource "aws_dynamodb_table" "jokes-dynamodb-table" {
  name           = "Jokes_DynamoDB_Table"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "id"
  range_key      = "timestamp"

  attribute {
    name = "id"
    type = "S"
  }
  attribute {
    name = "timestamp"
    type = "S"
  }
}

################################################################################
# Create the security group for Lambda Function
################################################################################
resource "aws_security_group" "lambda_security_group" {
  description = "Allow traffic for Lambda Function"
  vpc_id      = module.vpc.vpc_id

  dynamic "ingress" {
    for_each = var.sg_ingress_ports
    iterator = sg_ingress

    content {
      description = sg_ingress.value["description"]
      from_port   = sg_ingress.value["port"]
      to_port     = sg_ingress.value["port"]
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

################################################################################
# Creating VPC endpoint attached to private subnets containing Lambda Function
################################################################################
resource "aws_vpc_endpoint" "sqs_vpc_ep_interface" {
  vpc_id              = module.vpc.vpc_id
  vpc_endpoint_type   = "Interface"
  service_name        = "com.amazonaws.${var.aws_region}.dynamodb"
  subnet_ids          = [module.vpc.private_subnets[0], module.vpc.private_subnets[1]]
  private_dns_enabled = false
  security_group_ids  = [aws_security_group.lambda_security_group.id]
}

################################################################################
# Lambda IAM role to assume the role
################################################################################
resource "aws_iam_role" "lambda_role" {
  name = "lambda_execution_role"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [{
      "Effect" : "Allow",
      "Principal" : {
        "Service" : "lambda.amazonaws.com"
      },
      "Action" : "sts:AssumeRole"
    }]
  })
}


################################################################################
# Create policy to acess the DynamoDB
################################################################################
resource "aws_iam_policy" "DynamoDBAccessPolicy" {
  name        = "DynamoDBAccessPolicy"
  description = "DynamoDBAccessPolicy"
  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Action" : [
            "dynamodb:List*",
            "dynamodb:DescribeReservedCapacity*",
            "dynamodb:DescribeLimits",
            "dynamodb:DescribeTimeToLive"
          ],
          "Resource" : "*",
          "Effect" : "Allow"
        },
        {
          "Action" : [
            "dynamodb:BatchGet*",
            "dynamodb:DescribeStream",
            "dynamodb:DescribeTable",
            "dynamodb:Get*",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:BatchWrite*",
            "dynamodb:CreateTable",
            "dynamodb:Delete*",
            "dynamodb:Update*",
            "dynamodb:PutItem"
          ],
          "Resource" : [
            "arn:aws:dynamodb:*:*:table/Jokes_DynamoDB_Table"
          ],
          "Effect" : "Allow"
        }
      ]
    }
  )
}

################################################################################
# Assign policy to the role
################################################################################
resource "aws_iam_policy_attachment" "lambda_basic_execution" {
  name       = "lambda_basic_execution"
  roles      = [aws_iam_role.lambda_role.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}


resource "aws_iam_policy_attachment" "lambda_eni_access" {
  name       = "lambda_eni_access"
  roles      = [aws_iam_role.lambda_role.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaENIManagementAccess"
}

resource "aws_iam_policy_attachment" "lambda_dynamodb_access" {
  name       = "lambda_dynamodb_access"
  roles      = [aws_iam_role.lambda_role.name]
  policy_arn = aws_iam_policy.DynamoDBAccessPolicy.arn
}

################################################################################
# Compressing lambda_handler function code
################################################################################
data "archive_file" "lambda_function_archive" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/lambda_function.zip"
}

################################################################################
# Creating lambda layer for requests python library
################################################################################
resource "aws_lambda_layer_version" "requests_layer" {
  filename            = "${path.module}/requests_layer.zip"
  layer_name          = "requests_layer"
  compatible_runtimes = ["python3.12"]
  source_code_hash    = filebase64sha256("${path.module}/requests_layer.zip")
}

################################################################################
# Creating Lambda Function
################################################################################
resource "aws_lambda_function" "get_joke_lambda_function" {
  function_name = "ChuckNorrisJokes_Lambda"
  filename      = "${path.module}/lambda_function.zip"

  runtime     = "python3.12"
  handler     = "chucknorris_jokes.lambda_handler"
  layers      = [aws_lambda_layer_version.requests_layer.arn]
  memory_size = 128
  timeout     = 5

  vpc_config {
    subnet_ids         = module.vpc.private_subnets
    security_group_ids = [aws_security_group.lambda_security_group.id]
  }

  environment {
    variables = {
      API_URL        = "https://api.chucknorris.io/jokes/random",
      DYNAMODB_TABLE = "Jokes_DynamoDB_Table"
    }
  }

  source_code_hash = data.archive_file.lambda_function_archive.output_base64sha256

  role = aws_iam_role.lambda_role.arn
}

################################################################################
# Creating CloudWatch Log group for Lambda Function
################################################################################
resource "aws_cloudwatch_log_group" "get_joke_lambda_function_cloudwatch" {
  name              = "/aws/lambda/${aws_lambda_function.get_joke_lambda_function.function_name}"
  retention_in_days = 30
}

################################################################################
# Creating Lambda Function URL for accessing it via browser
################################################################################
resource "aws_lambda_function_url" "chucknorris_function_url" {
  function_name      = aws_lambda_function.get_joke_lambda_function.function_name
  authorization_type = "NONE" # Change to "AWS_IAM" for restricted access
}

