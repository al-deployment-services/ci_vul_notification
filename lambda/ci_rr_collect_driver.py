from datetime import datetime
from lib import al_ci_client
from lib import AWSDynamo
import boto3
import json
import logging
import os
import time
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

LOG_LEVEL=logging.INFO
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

#TODO: migrate this to os.environment
COLLECT_WORKER_NAME = os.environ["COLLECT_WORKER_NAME"]
COLLECT_WORKER_INVOCATION = os.environ["COLLECT_WORKER_INVOCATION"]
DYNAMODB_REM_MAP_NAME = os.environ["DYNAMODB_REM_MAP_NAME"]
DYNAMODB_REM_CHECK_IN_MAP_NAME = os.environ["DYNAMODB_REM_CHECK_IN_MAP_NAME"]
DYNAMODB_EXP_VUL_MAP_NAME = os.environ["DYNAMODB_EXP_VUL_MAP_NAME"]
DYNAMODB_VUL_KEY_MAP_NAME = os.environ["DYNAMODB_VUL_KEY_MAP_NAME"]

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

def create_ttl_time(days):
    return int(time.time()) + (days * 86400)

def start_collector(event):
    currenttime = datetime.now()
    event["date_marker"] = currenttime.strftime('%Y/%m/%d %H:%M:%S')

    myDynamoTable = AWSDynamo.DynamoDBClient(event)
    PartitionKeyExpression = Key("account_id").eq(event['acc_id'])
    environments = myDynamoTable.query_table("ALL_ATTRIBUTES", PartitionKeyExpression)

    if environments:
        logger.info("Collect from CID: {0} - Env count: {1}".format(event['acc_id'], environments["Count"]))
        lambda_client = boto3.client('lambda')
        for environment in environments["Items"]:
            worker_event = event
            worker_event['env_id'] = environment['id']
            worker_event['source'] = "driver-collector"
            worker_event['db_name_check_in'] = DYNAMODB_REM_CHECK_IN_MAP_NAME

            #invoke worker for collecting remediations per environment
            worker_event['db_name'] = DYNAMODB_REM_MAP_NAME
            worker_event['query_type'] = "remediations"
            response = invoke_lambda(COLLECT_WORKER_NAME, worker_event, lambda_client, COLLECT_WORKER_INVOCATION)
            logger.info("Invoke: {0}:{1} - for CID: {2} - Env ID: {3} - Status: {4}".format(COLLECT_WORKER_NAME, worker_event['db_name'], worker_event['acc_id'], worker_event["env_id"], response))

            #invoke worker for collecting exposure per environment
            worker_event['db_name'] = DYNAMODB_EXP_VUL_MAP_NAME
            worker_event['query_type'] = "exposure"
            response = invoke_lambda(COLLECT_WORKER_NAME, worker_event, lambda_client, COLLECT_WORKER_INVOCATION)
            logger.info("Invoke: {0}:{1} - for CID: {2} - Env ID: {3} - Status: {4}".format(COLLECT_WORKER_NAME, worker_event['db_name'], worker_event['acc_id'], worker_event["env_id"], response))

            #invoke worker for collecting vulnerability per environment
            worker_event['db_name'] = DYNAMODB_VUL_KEY_MAP_NAME
            worker_event['query_type'] = "vulnerability"
            response = invoke_lambda(COLLECT_WORKER_NAME, worker_event, lambda_client, COLLECT_WORKER_INVOCATION)
            logger.info("Invoke: {0}:{1} - for CID: {2} - Env ID: {3} - Status: {4}".format(COLLECT_WORKER_NAME, worker_event['db_name'], worker_event['acc_id'], worker_event["env_id"], response))

def lambda_handler(event, context):
    if event["source"] == "master-collector" :
        logger.info("Start Operations : {0} - Driver Type: {1}".format(datetime.now(), event['driver']))
        if event["driver"] == "collector":
            start_collector(event)
        else:
            logger.error("Invalid caller: {0} - expecting: collector".format(event['driver']))
    else:
        logger.error("Event Source not supported: {0}".format(event["source"]))
