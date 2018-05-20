from lib import al_ci_client
from lib import AWSDynamo
from datetime import datetime
import boto3
import requests
import logging
import json
import os
from base64 import b64decode
from botocore.exceptions import ClientError
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#Temp to be removed
from boto3.dynamodb.conditions import Key, Attr

LOG_LEVEL=logging.INFO
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

COLLECT_DRIVER_NAME = os.environ["COLLECT_DRIVER_NAME"]
COLLECT_DRIVER_INVOCATION = os.environ["COLLECT_DRIVER_INVOCATION"]
REPORTER_DRIVER_NAME = os.environ["REPORTER_DRIVER_NAME"]
REPORTER_DRIVER_INVOCATION = os.environ["REPORTER_DRIVER_INVOCATION"]
MONITOR_WORKER_NAME = os.environ["MONITOR_WORKER_NAME"]
MONITOR_WORKER_INVOCATION = os.environ["MONITOR_WORKER_INVOCATION"]
DYNAMODB_ENV_MAP_NAME = os.environ["DYNAMODB_ENV_MAP_NAME"]
DYNAMODB_CID_MAP_NAME = os.environ["DYNAMODB_CID_MAP_NAME"]
DYNAMODB_REGION = os.environ["DYNAMODB_REGION"]

def invoke_lambda(lambda_name, lambda_event, lambda_client, invoke_mode):
    try:
        #invoke lambda async, worker responsible for downstream error handler
        response = lambda_client.invoke(FunctionName=lambda_name, InvocationType=invoke_mode, Payload = bytes(json.dumps(lambda_event)))
        if response["StatusCode"] == 202 or response["StatusCode"] == 200:
            return True
        else:
            return response["FunctionError"]
    except ClientError as e:
        logger.error(e.response['Error']['Message'] + ": " + lambda_name)
        return False

def start_driver_reporter(event):
    myDynamoTable = AWSDynamo.DynamoDBClient(event)
    if event['parent_cid'] != "ALL":
        #Query for child CID based on parent CID
        PartitionKeyExpression = Key("parent_cid").eq(event['parent_cid'])
        KeyConditionExpression = PartitionKeyExpression
        accounts = myDynamoTable.query_table("ALL_ATTRIBUTES", KeyConditionExpression)
    else:
        #Scan table for all CID
        FilterExpression = Key('parent_cid').gt("1")
        accounts = myDynamoTable.scan_table("ALL_ATTRIBUTES", FilterExpression)

    if accounts:
        logger.info("Collect from Parent CID: {0} - Child CID count: {1}".format(event['parent_cid'], accounts["Count"]))
        lambda_client = boto3.client('lambda')

        for account in accounts["Items"]:
            driver_event = account
            driver_event['acc_id'] = driver_event.pop('id')
            driver_event['source'] = "master-reporter"
            driver_event['driver'] = event['driver']
            driver_event['db_name'] = DYNAMODB_ENV_MAP_NAME
            driver_event['db_region'] = DYNAMODB_REGION
            driver_event['log_level'] = event['log_level']

            #invoke driver to start collecting info for this respective CID
            response = invoke_lambda(REPORTER_DRIVER_NAME, driver_event, lambda_client, REPORTER_DRIVER_INVOCATION)
            logger.info("Invoke: {0}:{1} - for CID: {2} - Status: {3}".format(REPORTER_DRIVER_NAME, driver_event['db_name'], driver_event['acc_id'], response))

def start_driver_collector(event):
    myDynamoTable = AWSDynamo.DynamoDBClient(event)
    if event['parent_cid'] != "ALL":
        #Query for child CID based on parent CID
        PartitionKeyExpression = Key("parent_cid").eq(event['parent_cid'])
        KeyConditionExpression = PartitionKeyExpression
        accounts = myDynamoTable.query_table("ALL_ATTRIBUTES", KeyConditionExpression)
    else:
        #Scan table for all CID
        FilterExpression = Key('parent_cid').gt("1")
        accounts = myDynamoTable.scan_table("ALL_ATTRIBUTES", FilterExpression)

    if accounts:
        logger.info("Collect from Parent CID: {0} - Child CID count: {1}".format(event['parent_cid'], accounts["Count"]))
        lambda_client = boto3.client('lambda')
        for account in accounts["Items"]:
            driver_event = account
            driver_event['acc_id'] = driver_event.pop('id')
            driver_event['source'] = "master-collector"
            driver_event['driver'] = event['driver']
            driver_event['db_name'] = DYNAMODB_ENV_MAP_NAME
            driver_event['db_region'] = DYNAMODB_REGION
            driver_event['log_level'] = event['log_level']

            #invoke driver to start collecting info for this respective CID
            response = invoke_lambda(COLLECT_DRIVER_NAME, driver_event, lambda_client, COLLECT_DRIVER_INVOCATION)
            logger.info("Invoke: {0}:{1} - for CID: {2} - Status: {3}".format(COLLECT_DRIVER_NAME, driver_event['db_name'], driver_event['acc_id'], response))

def start_monitor(event):
    myDynamoTable = AWSDynamo.DynamoDBClient(event)
    if event['parent_cid'] != "ALL":
        #Query for child CID based on parent CID
        PartitionKeyExpression = Key("parent_cid").eq(event['parent_cid'])
        KeyConditionExpression = PartitionKeyExpression
        accounts = myDynamoTable.query_table("ALL_ATTRIBUTES", KeyConditionExpression)
    else:
        #Scan table for all CID
        FilterExpression = Key('parent_cid').gt("1")
        accounts = myDynamoTable.scan_table("ALL_ATTRIBUTES", FilterExpression)

    if accounts:
        logger.info("Monitor from Parent CID: {0} - Child CID count: {1}".format(event['parent_cid'], accounts["Count"]))
        lambda_client = boto3.client('lambda')
        for account in accounts["Items"]:
            worker_event = account
            worker_event['acc_id'] = worker_event.pop('id')
            worker_event['source'] = "driver-monitor"
            worker_event['driver'] = "monitor"
            worker_event['db_name'] = DYNAMODB_ENV_MAP_NAME
            worker_event['db_region'] = DYNAMODB_REGION
            worker_event['log_level'] = "info"

            #invoke worker to start collecting info for this respective CID
            response = invoke_lambda(MONITOR_WORKER_NAME, worker_event, lambda_client, MONITOR_WORKER_INVOCATION)
            logger.info("Invoke: {0}:{1} - for CID: {2} - Status: {3}".format(MONITOR_WORKER_NAME, worker_event['db_name'], worker_event['acc_id'], response))


def lambda_handler(event, context):
    if event["source"] == "aws.event" :
        logger.info("Start Operations : {0} - Master - Type: {1}".format(datetime.now(), event['driver']))
        event["db_name"] = DYNAMODB_CID_MAP_NAME
        event["db_region"] = DYNAMODB_REGION

        if event["driver"] == "collector":
            start_driver_collector(event)
        elif event['driver'] == "reporter" or event['driver'] == "sender":
            start_driver_reporter(event)
        elif event['driver'] == "monitor":
            start_monitor(event)
        else:
            logger.error("Invalid caller: {0} - expecting: reporter".format(event['driver']))
    else:
        logger.error("Event Source not supported: {0}".format(event["source"]))
