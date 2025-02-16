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