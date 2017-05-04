import json
import logging
import base64
import os
import boto3


def auth(event, context):

    log(event)

    method = event['methodArn']
    token = event['authorizationToken'].split().pop()
    decoded_token = base64.b64decode(token).decode()

    username, password = decoded_token.split(':', 1)

    dynamodb = boto3.client('dynamodb')
    user = dynamodb.get_item(
        TableName=os.environ['DYNAMODB_TABLE'],
        Key={'username': {'S': '{}'.format(username)}}
    )
    effect = 'Deny'
    if 'Item' not in user:
        effect = 'Deny'
    elif user['Item']['password']['S'] == password:
        effect = 'Allow'

    return gen_policy(username, effect, method)


def gen_policy(principal_id, effect, resource):
    auth_resp = {}
    auth_resp['principalId'] = principal_id
    if effect and resource:
        policy_doc = {}
        policy_doc['Version'] = '2012-10-17'
        policy_doc['Statement'] = []
        statement = {}
        statement['Action'] = 'execute-api:Invoke'
        statement['Effect'] = effect
        statement['Resource'] = resource
        policy_doc['Statement'].append(statement)
        auth_resp['policyDocument'] = policy_doc
    return auth_resp


def log(msg):
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.info(json.dumps(msg, indent=4))


def validate(event):
    if 'methodArn' in event and 'authorizationToken' in event and 'Basic ' in event['authorizationToken']:
        return True
    return False
