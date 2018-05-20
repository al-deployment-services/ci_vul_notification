from lib import al_ci_client
from lib import AWSDynamo
from datetime import datetime
import requests
import logging
import boto3
from base64 import b64decode
from boto3.dynamodb.conditions import Key, Attr
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOG_LEVEL=logging.DEBUG
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

def dynamodb_get_env_cid(event, dynamod_db_client):
    #Query DYNAMODB for ENVID based on CID
    PartitionKeyExpression = Key("account_id").eq(event['acc_id'])
    KeyConditionExpression = PartitionKeyExpression
    return dynamod_db_client.query_table("ALL_ATTRIBUTES", KeyConditionExpression)

def ci_get_env_cid(args):
    myCI = al_ci_client.CloudInsight(args)
    query_args={}
    query_args['type'] = 'aws'
    query_args['defender_support'] = 'false'
    return myCI.get_environments_by_cid_custom(query_args)

def monitor_per_cid(event):
    myDynamoTable = AWSDynamo.DynamoDBClient(event)

    logger.info("Start Operations : {0} - DynamoDB Query Env ID for CID: {1}".format(datetime.now(), event["acc_id"]))
    db_environments = dynamodb_get_env_cid(event, myDynamoTable)
    logger.info("Finish Operations : {0} - Env ID found: {1}".format(datetime.now(), db_environments["Count"]))

    logger.info("Start Operations : {0} - API Query Env ID for CID: {1}".format(datetime.now(), event["acc_id"]))
    ci_environments = ci_get_env_cid(event)
    logger.info("Finish Operations : {0} - Env ID found: {1}".format(datetime.now(), ci_environments["count"]))

    if ci_environments:
        #Find new environment
        new_env_counter = 0
        for env in ci_environments["environments"]:
            bool_env_exist = False
            for existing_env in db_environments["Items"]:
                if env["id"] == existing_env["id"]:
                    bool_env_exist = True
                    break
            if bool_env_exist == False:
                if myDynamoTable.single_write_to_table(env):
                    logger.info("Add new Env ID: {0} - to DynamoDB - for CID: {1}".format(env["id"], event["acc_id"]))
                    new_env_counter+=1
                else:
                    logger.error("Error while trying to add new Env ID: {0} - to DynamoDB - for CID: {1}".format(env["id"], event["acc_id"]))

        logger.info("Total new Env added for CID: {0} is: {1}".format(event["acc_id"], new_env_counter))

        #Find old environment to be removed
        old_env_counter = 0
        for existing_env in db_environments["Items"]:
            bool_env_exist = False
            for env in ci_environments["environments"]:
                if env["id"] == existing_env["id"]:
                    bool_env_exist = True
                    break

            if bool_env_exist == False:
                item_key = {}
                item_key['account_id'] = existing_env['account_id']
                item_key['id'] = existing_env['id']
                if myDynamoTable.single_delete_to_table(keys=item_key):
                    logger.info("Removed Old Env ID: {0} - from DynamoDB - for CID: {1}".format(existing_env["id"], existing_env["account_id"]))
                    old_env_counter+=1
                else:
                    logger.error("Error while trying to remove old Env ID: {0} - from DynamoDB - for CID: {1}".format(existing_env["id"], existing_env["account_id"]))

        logger.info("Total old Env removed for CID: {0} is: {1}".format(event["acc_id"], old_env_counter))

def lambda_handler(event, context):
    if event["source"] == "driver-monitor" :
        if event['driver'] == "monitor":
            plaintext = boto3.client('kms').decrypt(CiphertextBlob=b64decode(event["password"]))['Plaintext']
            event["password"] = plaintext
            monitor_per_cid(event)
        else:
            logger.error("Invalid caller: {0} - expecting: collector".format(event['driver']))
    else:
        logger.error("Event Source not supported: {0}".format(event["source"]))
