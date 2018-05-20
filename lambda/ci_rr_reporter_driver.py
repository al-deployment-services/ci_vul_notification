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
from boto3.dynamodb.conditions import Key, Attr

LOG_LEVEL=logging.INFO
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

#TODO: migrate this to os.environment
REPORTER_WORKER_INVOCATION = os.environ["REPORTER_WORKER_INVOCATION"]
REPORTER_WORKER_NAME = os.environ["REPORTER_WORKER_NAME"]
REPORTER_SENDER_INVOCATION = os.environ["REPORTER_SENDER_INVOCATION"]
REPORTER_SENDER_NAME = os.environ["REPORTER_SENDER_NAME"]

DYNAMODB_ENV_CHECKIN_MAP_NAME = os.environ["DYNAMODB_ENV_CHECKIN_MAP_NAME"]
DYNAMODB_REM_MAP_NAME = os.environ["DYNAMODB_REM_MAP_NAME"]
DYNAMODB_EXP_VUL_MAP_NAME = os.environ["DYNAMODB_EXP_VUL_MAP_NAME"]
DYNAMODB_VUL_KEY_MAP_NAME = os.environ["DYNAMODB_VUL_KEY_MAP_NAME"]
DYNAMODB_VUL_KEY_MAP_ADD_NAME = os.environ["DYNAMODB_VUL_KEY_MAP_ADD_NAME"]
DYNAMODB_VUL_KEY_MAP_RMV_NAME = os.environ["DYNAMODB_VUL_KEY_MAP_RMV_NAME"]
DYNAMODB_VUL_DATA_MAP_NAME = os.environ["DYNAMODB_VUL_DATA_MAP_NAME"]
DYNAMODB_VUL_DATA_MAP_TTL = os.environ["DYNAMODB_VUL_DATA_MAP_TTL"]
DYNAMODB_REGION = os.environ["DYNAMODB_REGION"]
DYNAMODB_INDEX_NAME = os.environ["DYNAMODB_INDEX_NAME"]

def find_last_checkin(args, db_table):
    PartitionKeyExpression = Key("id").eq(args['env_id'])
    response = db_table.query_table(
        "ALL_ATTRIBUTES",
        PartitionKeyExpression,
        False
        )
    if (response["Count"] >= 2):
        return response["Items"][0], response["Items"][1]
    else:
        return None, None

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

def start_reporter(event):
    myDynamoTable = AWSDynamo.DynamoDBClient(event)
    PartitionKeyExpression = Key("account_id").eq(event['acc_id'])
    environments = myDynamoTable.query_table("ALL_ATTRIBUTES", PartitionKeyExpression)
    if environments:
        logger.info("Report for CID: {0} - Env count: {1}".format(event['acc_id'], environments["Count"]))
        lambda_client = boto3.client('lambda')

        checkin_args = {}
        checkin_args["db_name"] = DYNAMODB_ENV_CHECKIN_MAP_NAME
        checkin_args["db_region"] = DYNAMODB_REGION
        checkin_args["log_level"] = event['log_level']
        myCheckInTable = AWSDynamo.DynamoDBClient(checkin_args)

        for environment in environments["Items"]:
            checkin_args["env_id"] = environment['id']
            currentdate, previousdate = find_last_checkin(checkin_args, myCheckInTable)

            if currentdate and previousdate:
                logger.info("Check in data - CID: {0} - Env ID: {1} - Current check in: {2} - Previous check in: {3}".format(
                    event['acc_id'],
                    environment["id"],
                    currentdate["date_marker"],
                    previousdate["date_marker"]
                    ))

                worker_event = event
                worker_event['env_id'] = environment['id']
                worker_event['env_name'] = environment['name']
                worker_event['type_id'] = environment['type_id']
                worker_event['currentdate'] = currentdate["date_marker"]
                worker_event['previousdate'] = previousdate["date_marker"]

                if event['driver'] == "reporter":
                    worker_event['source'] = "driver-reporter"
                    worker_event['index_name'] = DYNAMODB_INDEX_NAME

                    #invoke worker for reporting remediations per environment
                    worker_event['db_name'] = DYNAMODB_REM_MAP_NAME
                    worker_event['query_type'] = "remediations"
                    response = invoke_lambda(REPORTER_WORKER_NAME, worker_event, lambda_client, REPORTER_WORKER_INVOCATION)
                    logger.info("Invoke: {0}:{1} - for CID: {2} - Env ID: {3} - Status: {4}".format(REPORTER_WORKER_NAME, worker_event['db_name'], worker_event['acc_id'], worker_event["env_id"], response))

                    #invoke worker for reporting vul exposure per environment
                    worker_event['db_name'] = DYNAMODB_EXP_VUL_MAP_NAME
                    worker_event['query_type'] = "exposure"
                    response = invoke_lambda(REPORTER_WORKER_NAME, worker_event, lambda_client, REPORTER_WORKER_INVOCATION)
                    logger.info("Invoke: {0}:{1} - for CID: {2} - Env ID: {3} - Status: {4}".format(REPORTER_WORKER_NAME, worker_event['db_name'], worker_event['acc_id'], worker_event["env_id"], response))

                    #invoke worker for reporting vulnerability per environment
                    worker_event['db_name'] = DYNAMODB_VUL_KEY_MAP_NAME
                    worker_event["db_name_add_prep"] = DYNAMODB_VUL_KEY_MAP_ADD_NAME
                    worker_event["db_name_rmv_prep"] = DYNAMODB_VUL_KEY_MAP_RMV_NAME
                    worker_event['query_type'] = "vulnerability"
                    response = invoke_lambda(REPORTER_WORKER_NAME, worker_event, lambda_client, REPORTER_WORKER_INVOCATION)
                    logger.info("Invoke: {0}:{1} - for CID: {2} - Env ID: {3} - Status: {4}".format(REPORTER_WORKER_NAME, worker_event['db_name'], worker_event['acc_id'], worker_event["env_id"], response))

                elif event['driver'] == "sender":
                    worker_event['source'] = "driver-sender"
                    worker_event['db_name'] = ""
                    worker_event['db_name_vul_data'] = DYNAMODB_VUL_DATA_MAP_NAME
                    worker_event['db_ttl_vul_data'] = DYNAMODB_VUL_DATA_MAP_TTL
                    worker_event['db_name_vul_key'] = DYNAMODB_VUL_KEY_MAP_NAME
                    worker_event["db_name_add_prep"] = DYNAMODB_VUL_KEY_MAP_ADD_NAME
                    worker_event["db_name_rmv_prep"] = DYNAMODB_VUL_KEY_MAP_RMV_NAME
                    worker_event["index_name"] = DYNAMODB_INDEX_NAME
                    worker_event['query_type'] = "vulnerability"
                    response = invoke_lambda(REPORTER_SENDER_NAME, worker_event, lambda_client, REPORTER_SENDER_INVOCATION)
                    logger.info("Invoke: {0}:{1} - for CID: {2} - Env ID: {3} - Status: {4}".format(REPORTER_SENDER_NAME, worker_event['db_name'], worker_event['acc_id'], worker_event["env_id"], response))

            else:
                logger.error("Check in data - CID: {0} - Env ID: {1} - No enough history, minimum 2 checkin required".format(event['acc_id'], environment["id"]))

def lambda_handler(event, context):
    if event["source"] == "master-reporter" :
        logger.info("Start Operations : {0} - Driver Type: {1}".format(datetime.now(), event['driver']))
        if event['driver'] == "reporter" or event['driver'] == "sender":
            start_reporter(event)
        else:
            logger.error("Invalid caller: {0} - expecting: collector".format(event['driver']))
    else:
        logger.error("Event Source not supported: {0}".format(event["source"]))
