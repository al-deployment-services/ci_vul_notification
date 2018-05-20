from lib import al_ci_client
from lib import AWSDynamo
from datetime import datetime
import boto3
import requests
import logging
import json
import time
from base64 import b64decode
from botocore.exceptions import ClientError
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOG_LEVEL=logging.INFO
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

def error_handler(event, source_collector):
    sqs = boto3.resource('sqs')
    queue = sqs.get_queue_by_name(QueueName='ci_rr_collect_worker_queue')
    event["function_name"] = source_collector
    response = queue.send_message(MessageBody=json.dumps(event))
    print (response)

def create_ttl_time(days):
    return int(time.time()) + (days * 86400)

def collect_remediation(args, db_table):
    myCI = al_ci_client.CloudInsight(args)
    myEnv = myCI.get_environments()
    if myEnv:
        remediations = myCI.get_remediations_short()
        logger.info("Batch write to: {0} - CID: {1} - EnvId: {2} - Total: {3}".format(args['db_name'], myEnv["account_id"], myEnv["id"], remediations["remediations"]["rows"]))
        if db_table.write_to_table(remediations["remediations"]["assets"], args["date_marker"], ttl=create_ttl_time(int(args["ttl"]))):
            logger.info("Batch write Completed")
        else:
            error_handler(args, "collect_remediation")
    else:
        logger.error("Cant read environment ID: {0}".format(args['env_id']))

def collect_exposure(args, db_table):
    myCI = al_ci_client.CloudInsight(args)
    myEnv = myCI.get_environments()
    if myEnv:
        remediations = myCI.get_remediations_short()
        item_payload = []
        for remediation in remediations["remediations"]["assets"]:
            for exposure in remediation["vulnerabilities"]:
                exposure["remediation_id"] = remediation["remediation_id"]
                exposure["deployment_id"] = remediation["deployment_id"]
                exposure["account_id"] = remediation["account_id"]
                exposure["vul_map_sort_key"] = str(remediation["deployment_id"]) + "/" + str(args["date_marker"])
                item_payload.append(exposure)

        logger.info("Batch write to: {0} - CID: {1} - EnvId: {2} - Total: {3}".format(args['db_name'], myEnv["account_id"], myEnv["id"], len(item_payload)))
        if db_table.write_to_table(item_payload, args["date_marker"], ['vulnerability_id', 'vul_map_sort_key'], ttl=create_ttl_time(int(args["ttl"]))):
            logger.info("Batch write Completed")
    else:
        logger.error("Cant read environment ID: {0}".format(args['env_id']))

def collect_vulnerability(args, db_table):
    myCI = al_ci_client.CloudInsight(args)
    myEnv = myCI.get_environments()
    if myEnv:
        query_args = {}
        query_args["asset_types"] = "vulnerability"
        vulnerabilities = myCI.get_asset_custom(query_args)
        item_payload = []
        for vulnerability in vulnerabilities["assets"]:
            temp_item = {}
            temp_item["account_id"] = myEnv["account_id"]
            temp_item["deployment_id"] = myEnv["id"]
            temp_item["key"] = vulnerability[0]["key"]
            temp_item["name"] = vulnerability[0]["name"]
            temp_item["vulnerability_id"] = vulnerability[0]["vulnerability_id"]
            temp_item["threat_score"] = vulnerability[0]["threat_score"]
            #DynamoDB did not support empty attributes value
            if vulnerability[0]["details"] != "":
                temp_item["details"] = vulnerability[0]["details"]
            else:
                temp_item["details"] = "N/A"

            temp_item["disposed"] = vulnerability[0]["disposed"]
            temp_item["cvss_score"] = vulnerability[0]["cvss_score"]
            item_payload.append(temp_item)

        logger.info("Batch write to: {0} - CID: {1} - EnvId: {2} - Total: {3}".format(args['db_name'], myEnv["account_id"], myEnv["id"], len(item_payload)))
        db_table.write_to_table(item_payload, args["date_marker"], ttl=create_ttl_time(int(args["ttl"])))
        logger.info("Batch write sent")

    else:
        logger.error("Cant read environment ID: {0}".format(args['env_id']))

def write_check_in(event):
    checkin_event = {}
    checkin_event["log_level"] = "info"
    checkin_event["db_name"] = event["db_name_check_in"]
    checkin_event["db_region"] = event["db_region"]
    myCheckInTable = AWSDynamo.DynamoDBClient(checkin_event)

    #write timestamp of collection to the checkin table
    checkin_payload = {}
    checkin_payload["id"] = event['env_id']
    checkin_payload["acc_id"] =event['acc_id']
    checkin_payload["date_marker"] = event["date_marker"]
    checkin_payload["TTL"] = create_ttl_time(60)
    response = myCheckInTable.single_write_to_table(checkin_payload)
    logger.info("Check in to: {0} at {1} - for CID: {2} - Env ID: {3} - Status: {4}".format(checkin_event["db_name"], event["date_marker"], event['acc_id'], event["env_id"], response))


def lambda_handler(event, context):
    if event["source"] == "driver-collector" :
        if event['driver'] == "collector":
            myDynamoTable = AWSDynamo.DynamoDBClient(event)
            plaintext = boto3.client('kms').decrypt(CiphertextBlob=b64decode(event["password"]))['Plaintext']
            event["password"] = plaintext
            logger.info("Start Operations : {0} - Event Type: {1}".format(datetime.now(), event['query_type']))
            if event['query_type'] == "remediations":
                collect_remediation(event, myDynamoTable)
                write_check_in(event)
            elif event['query_type'] == "exposure":
                collect_exposure(event, myDynamoTable)
                write_check_in(event)
            elif event['query_type'] == "vulnerability":
                collect_vulnerability(event, myDynamoTable)
                write_check_in(event)
            else:
                logger.error("Invalid query_type: {0}".format(event['query_type']))
        else:
            logger.error("Invalid caller: {0} - expecting: collector".format(event['driver']))
    else:
        logger.error("Event Source not supported: {0}".format(event["source"]))
