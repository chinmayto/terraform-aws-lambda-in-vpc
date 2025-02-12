import json
import requests
import os
import boto3

from datetime import datetime

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Jokes_DynamoDB_Table')

def lambda_handler(event, context):
    response = requests.get(os.environ['API_URL'])
    jokeid = response.json().get("id", "Null")
    joke = response.json().get("value", "No joke found.")
    now = datetime.now()

    table.put_item(
        Item={
            'id': jokeid,
            'value': joke,
            'timestamp': now.strftime("%d/%m/%Y %H:%M:%S")
        }
    )

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(joke)
    }