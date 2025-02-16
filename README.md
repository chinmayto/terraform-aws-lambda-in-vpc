# Configuring a Lambda Function in a VPC to access external API via NAT Gateway and Store in DynamoDB using AWS PrivateLink

### Introduction

AWS Lambda functions running inside a Virtual Private Cloud (VPC) provide enhanced security, network isolation, and direct access to other AWS services within the VPC. By placing Lambda in a VPC, we ensure it can securely communicate with private resources like databases while also accessing external APIs via a NAT Gateway. This setup is crucial for workloads that require controlled outbound internet access and private service interactions.

In this blog, we will configure a Lambda function inside a VPC that fetches Chuck Norris jokes from chucknorris.io via a NAT Gateway and stores them in a DynamoDB table using AWS PrivateLink.

### Architecture Overview
![alt text](/images/architecture.png)

### Step 1: Create a VPC with Public and Private Subnets
Create a new VPC with two public subnets and two private subnets. The public subnets will host the NAT Gateway, and the private subnets will be used for Lambda.
A NAT Gateway is required to allow private subnets to access the internet while keeping them secure.
```terraform
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
```

### Step 2: Create a DynamoDB Table
We need a DynamoDB table to store the Chuck Norris jokes.
```terraform
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
```

### Step 3: Create a VPC Interface Endpoint for DynamoDB
Instead of routing traffic over the internet, we will use AWS PrivateLink to securely access DynamoDB from private subnets.
We will create and attach a security group to VPC endpoint which will contain or lambda function.

```terraform
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
```

### Step 4: Create IAM Role for Lambda
The Lambda function requires an IAM role with permissions to access DynamoDB and VPC resources.
It will need acess to create ENIs for accessing the services via PrivateLink

```terraform
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
```

### Step 5: Create a Lambda Function
The Lambda function will:
1. Fetch a joke from chucknorris.io
2. Store the joke in the DynamoDB table

(Note: when lambda function gets called from function URL, it causes duplicate hits to lambda as browser requests favicons, the code will gnore the favicon requests)

```python
import json
import requests
import os
import boto3

from datetime import datetime

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.getenv('DYNAMODB_TABLE'))

def lambda_handler(event, context):
    # Ignore the favicon requests when called from browse using function URL
    path = event.get("rawPath", "")
    if path == "/favicon.ico":
        return { 'statusCode': 404, 'body': 'Not Found' }

    # get the joke from chucknorris.io api
    response = requests.get(os.environ['API_URL'])
    jokeid = response.json().get("id", "Null")
    joke = response.json().get("value", "No joke found.")
    now = datetime.now()

    # put the joke details into dynamodb
    table.put_item(
        Item={
            'id': jokeid,
            'value': joke,
            'timestamp': now.strftime("%d/%m/%Y %H:%M:%S")
        }
    )

    # return html respose
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(joke)
    }
```

Create a lambda layer for requsts library and create lambda function with function URL
```terraform
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
# Creating Lambda Function URL for accessing it via browser
################################################################################
resource "aws_lambda_function_url" "chucknorris_function_url" {
  function_name      = aws_lambda_function.get_joke_lambda_function.function_name
  authorization_type = "NONE" # Change to "AWS_IAM" for restricted access
}
```

### Step 6: Create cloudwatch log group for logging
```terraform
################################################################################
# Creating CloudWatch Log group for Lambda Function
################################################################################
resource "aws_cloudwatch_log_group" "get_joke_lambda_function_cloudwatch" {
  name              = "/aws/lambda/${aws_lambda_function.get_joke_lambda_function.function_name}"
  retention_in_days = 30
}
```
### Steps to Run Terraform
Follow these steps to execute the Terraform configuration:
```terraform
terraform init
terraform plan 
terraform apply -auto-approve
```

Upon successful completion, Terraform will provide relevant outputs.
```terraform
Apply complete! Resources: 29 added, 0 changed, 0 destroyed.

Outputs:

lambda_function_url = "https://co564k26i32eowzqlum6xm5muy0logkk.lambda-url.us-east-1.on.aws/"
```

### Testing
Lambda Function in VPC:

![alt text](/images/lambda_in_vpc.png)

DynamoDB Table:

![alt text](/images/dynamodb_table.png)

Test Event:

![alt text](/images/test_event.png)

DynamoDB Scan:

![alt text](/images/dbscan_1.png)

Lambda Invocation using Function URL
![alt text](/images/lambda_function_url.png)

DynamoDB scan:

![alt text](/images/dbscan_2.png)

CloudWatch Logs:

![alt text](/images/cloudwatch.png)

### Cleanup
Remember to stop AWS components to avoid large bills.
```terraform
terraform destroy -auto-approve
```

### Conclusion

This architecture provides a secure way to access DynamoDB using PrivateLink while allowing the Lambda function to communicate with external APIs through a NAT Gateway.

### References
GitHub Repo: https://github.com/chinmayto/terraform-aws-lambda-in-vpc