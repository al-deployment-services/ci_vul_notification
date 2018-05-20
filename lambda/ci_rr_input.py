from lib import AWSDynamo
from lib import al_ci_client
from datetime import datetime
import requests
import boto3
import logging
import os
from base64 import b64encode
from botocore.exceptions import ClientError
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


LOG_LEVEL=logging.INFO
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

DYNAMODB_CID_MAP_NAME = os.environ["DYNAMODB_CID_MAP_NAME"]
DYNAMODB_REGION = os.environ["DYNAMODB_REGION"]
KMS_KEY = os.environ["KMS_KEY"]

def validate_cred(args):
    try:
        print (args)
        myCred = al_ci_client.CloudInsight(args)
        logger.info(myCred.token)
        return myCred.token
    except ClientError as e:
        logger.error(e.response['Error']['Message'])
        return False

def validate_cid(args):
    myCID = al_ci_client.CloudInsight(args)
    cid_response = myCID.get_cid_details(args['id'])
    if cid_response:
        return cid_response['active']
    else:
        return False

def start_register(event):
    validate_cid(event)

    try:
        encrypted = boto3.client('kms').encrypt(
            KeyId=KMS_KEY,
            Plaintext=event['password']
        )

        event["password"] = b64encode(encrypted['CiphertextBlob'])
        logger.info (event["password"])

        register_event = {}
        register_event["log_level"] = "info"
        register_event["db_name"] = DYNAMODB_CID_MAP_NAME
        register_event["db_region"] = DYNAMODB_REGION
        myRegisterTable = AWSDynamo.DynamoDBClient(register_event)

        payload = {}
        payload["id"] = event["id"]
        payload["user"] = event["user"]
        payload["password"] = event["password"]
        payload["parent_cid"] = event["parent_cid"]
        payload["yarp"] = event["yarp"]
        payload["output"] = event["output"]
        payload["sns_arn"] = event["sns_arn"]
        payload["s3_bucket"] = event["s3_bucket"]
        payload["ttl"] = event["ttl"]
        payload["filter"] = event["filter"]

        response = myRegisterTable.single_write_to_table(payload)
        logger.info("Register to: {0} - for CID: {1} - Status: {2}".format(DYNAMODB_CID_MAP_NAME, event['id'], response))
        if response:
            response["Input"] = event
            response["Input"].pop("password")
            return "Successfully update DynamoDB"
        else:
            return "Failed to update DynamoDB"
    except ClientError as e:
        logger.error(e.response['Error']['Message'])
        return e.response['Error']['Message']

def lambda_handler(event, context):
    if event:
        if event["source"] == "aws.apigateway" :
            logger.info("Start Operations : {0} - Master - Type: {1}".format(datetime.now(), event['driver']))
            event["db_name"] = DYNAMODB_CID_MAP_NAME
            event["db_region"] = DYNAMODB_REGION
            event["log_level"] = "info"

            if event["driver"] == "register":
                if validate_cred(event) != False:
                    if validate_cid(event):
                        return start_register(event)
                    else:
                        logger.error("Invalid / Inactive CID: {0}".format(event['id']))
                        return "Invalid / Inactive CID: {0}".format(event['id'])
                else:
                    logger.error("Invalid Credentials for: {0}".format(event['user']))
                    return "Invalid Credentials for: {0}".format(event['user'])

            else:
                logger.error("Invalid caller: {0}".format(event['driver']))
                return "Invalid caller: {0}".format(event['driver'])
        else:
            logger.error("Event Source not supported: {0}".format(event["source"]))
            return "Event Source not supported: {0}".format(event["source"])
    else:
        return "No payload / incomplete provided"
