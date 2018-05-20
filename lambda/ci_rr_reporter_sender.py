from lib import al_ci_client
from lib import AWSDynamo
from datetime import datetime
import boto3
import requests
import logging
import json
import copy
import time
from base64 import b64decode
from botocore.exceptions import ClientError
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from boto3.dynamodb.conditions import Key, Attr

LOG_LEVEL=logging.INFO
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

def convert_to_list(input_data, item_key):
    temp_list = []
    for item in input_data:
        temp_list.append(item[item_key])
    return temp_list

def create_ttl_time(days):
    return int(time.time()) + (days * 86400)

def send_sns(sns_subject, sns_message, sns_arn):
    sns_client = boto3.client('sns')
    sns_response = sns_client.publish(
        TargetArn=sns_arn,
        Message=sns_message,
        Subject=sns_subject)
    return sns_response

def write_to_s3(args, payload):
    try:
        date_marker = datetime.strptime(str(args["currentdate"]),'%Y/%m/%d %H:%M:%S')
        filename = str(args["env_name"] + "_" + args["query_type"]) + "_detail_" + str(date_marker.strftime('%Y:%m:%d-%H:%M:%S')) + ".txt"
        s3 = boto3.resource('s3')
        object = s3.Object(args['s3_bucket'], str(args['type_id'] + '/' + str(datetime.now().strftime('%Y-%m-%d')) + '/' + filename))
        object.put(Body=payload.encode())
        return True

    except ClientError as e:
        return False

def find_severity_class(min_val, max_val):
    severity = []
    index = min_val
    while index <= max_val:
        if index > 6.9:
            severity.append("High")
            break
        elif index > 3.9:
            severity.append("Medium")
            index = 6.9
        elif index > 0:
            severity.append("Low")
            index = 3.9
        elif index == 0:
            severity.append("Info")
        index += 0.1
    return severity

def read_report_findings(args, db_table, index_name, index_partition_key, index_partition_value, index_sort_key, index_sort_value, table_partition_key, table_sort_key, read_mode, severity_filter):
    try:
        result = ""

        #Query list of ADDED / REMOVED vulnerability based on ENV ID and Date Marker index
        todays_report = db_table.query_table_with_index(
            "SPECIFIC_ATTRIBUTES",
            Key(index_partition_key).eq(index_partition_value) & Key(index_sort_key).eq(index_sort_value),
            index_name,
            "#a,#b",
            {"#a" : table_partition_key, "#b" : table_sort_key},
            True
        )

        if len(todays_report["Items"]) > 0:
            vul_event = copy.deepcopy(args)
            vul_event['db_name'] = args['db_name_vul_data']
            myVulLookupTable = AWSDynamo.DynamoDBClient(vul_event)

            vul_detail_event = copy.deepcopy(args)
            vul_detail_event['db_name'] = args['db_name_vul_key']
            myVulDetailTable = AWSDynamo.DynamoDBClient(vul_detail_event)

            for item in todays_report["Items"]:
                #Query the exposure name based on vulnerability ID
                exposure_name = myVulLookupTable.query_table(
                    "ALL_ATTRIBUTES",
                    Key("id").eq(item["vulnerability_id"])
                )
                if exposure_name["Count"] == 0:
                    logger.info("Cache miss for exposure id: {0} - attempting to query Cloud Insight API".format(item["vulnerability_id"]))
                    myCI = al_ci_client.CloudInsight(args)
                    #TODO: tidy up this mess - currently I am trying to match the returned data structure from DynamoDB query
                    exposure_name = {}
                    exposure_name["Items"] = []
                    exposure_name["Items"].append(myCI.get_vulnerability_map_custom(item["vulnerability_id"]))
                    exposure_name["Items"][0]["TTL"] = create_ttl_time(int(args["db_ttl_vul_data"]))

                    if len(exposure_name["Items"]) > 0:
                        logger.info("Found exposure id: {0} in CI API - attempting to store in DynamoDB cache".format(item["vulnerability_id"]))
                        if myVulLookupTable.single_write_to_table(exposure_name["Items"][0]):
                            logger.info("Successfully stored exposure id {0} in DynamoDB cache".format(item["vulnerability_id"]))
                        else:
                            logger.error("Failed to store exposure id {0} in DynamoDB cache".format(item["vulnerability_id"]))
                    else:
                        logger.error("Failed to find exposure id {0} in CI API - this vulnerability exposure will not be recorded".format(item["vulnerability_id"]))

                if exposure_name["Items"][0]["severity"] in severity_filter:
                    logger.info("Exposure: {0} - {1}".format(exposure_name["Items"][0]["description"], exposure_name["Items"][0]["severity"]))
                    result = result + "Exposure: {0} - {1}\n".format(exposure_name["Items"][0]["description"], exposure_name["Items"][0]["severity"])

                    #Query the vulnerability detail based on vulnerability ID and sort key (date marker)
                    vulnerabilities = db_table.query_table(
                        "ALL_ATTRIBUTES",
                        Key(table_partition_key).eq(item["vulnerability_id"]) & Key(table_sort_key).eq(item["vul_key_sort_key"])
                    )

                    #For each vulnerability keys, query the detail about that particular asset vulnerability
                    counter = 1
                    for vulnerability in vulnerabilities["Items"]:
                        #TODO: fix this upstream - where vulnerability_items can be duplicate when reporter worker run more than once
                        for vulnerability_key in set(vulnerability["vulnerability_items"]):
                            if read_mode == "removed":
                                date_marker = args["previousdate"]
                            elif read_mode == "added":
                                date_marker = args["currentdate"]
                            vulnerability_detail = myVulDetailTable.query_table(
                                "ALL_ATTRIBUTES",
                                Key("key").eq(vulnerability_key) & Key("date_marker").eq(date_marker)
                            )
                            logger.info("{0}.{1} - {2}".format(counter, vulnerability_detail["Items"][0]["key"], vulnerability_detail["Items"][0]["threat_score"]))
                            result = result + "{0}.{1} - {2}\n".format(counter, vulnerability_detail["Items"][0]["key"], vulnerability_detail["Items"][0]["threat_score"])
                            counter += 1
                    logger.info(" ")
                    result = result + "\n"

            if result == "":
                logger.info("No new vulnerability {0}\n".format(read_mode))
                result = "There is no vulnerability {0}.\n\n".format(read_mode)

            return result

        else:
            logger.info("No new vulnerability {0}\n".format(read_mode))
            result = "There is no vulnerability {0}.\n\n".format(read_mode)
            return result

    except ClientError as e:
        logger.error(e.response['Error']['Message'] + ": " + str(self.db_table))
        return None

def lambda_handler(event, context):
    if event["source"] == "driver-sender" :
        if event['driver'] == "sender":
            logger.info("Start Operations : {0} - Event Type: {1}".format(datetime.now(), event['query_type']))
            sns_output = ""
            sns_subject = ""

            if event['query_type'] == "vulnerability":
                plaintext = boto3.client('kms').decrypt(CiphertextBlob=b64decode(event["password"]))['Plaintext']
                event["password"] = plaintext

                sns_subject = "Detail Vulnerability Report"
                logger.info("Acc ID: {0} - Env Name: {1} - CID : {2} - Env ID: {3} \n".format( event['type_id'], event['env_name'], event['acc_id'],  event['env_id']))
                sns_output = sns_output + "Acc ID: {0} - Env Name: {1} - CID : {2} - Env ID: {3} \n".format( event['type_id'], event['env_name'], event['acc_id'],  event['env_id'])

                severity_filter = find_severity_class(float(event["filter"]["min"]), float(event["filter"]["max"]))
                logger.info("Filter vulnerability severity by: {0}\n".format(severity_filter))
                sns_output = sns_output + "Filter vulnerability severity by: {0}\n\n".format(severity_filter)

                logger.info("Vulnerabilities added:")
                sns_output = sns_output + "Vulnerabilities added:\n"
                event['db_name'] = event['db_name_add_prep']
                myAddedVul = AWSDynamo.DynamoDBClient(event)
                sns_output = sns_output + read_report_findings(event, myAddedVul, event["index_name"], "deployment_id", event["env_id"], "date_marker", event["currentdate"], "vulnerability_id", "vul_key_sort_key", "added", severity_filter)

                logger.info("Vulnerabilities removed:")
                sns_output = sns_output + "Vulnerabilities removed:\n"
                event['db_name'] = event['db_name_rmv_prep']
                myRemovedVul = AWSDynamo.DynamoDBClient(event)
                sns_output = sns_output + read_report_findings(event, myRemovedVul, event["index_name"], "deployment_id", event["env_id"], "date_marker", event["currentdate"], "vulnerability_id", "vul_key_sort_key", "removed", severity_filter)

            if sns_output != "" and sns_subject != "":
                if event['output'] == "S3":
                    s3_reponse = write_to_s3(event, sns_output)
                    logger.info("Writing report to S3 bucket: {0} - Status {1}".format(event['s3_bucket'], s3_reponse))
                elif event['output'] == "SNS":
                    sns_subject = sns_subject + " " + event["acc_id"] + " " + event["type_id"] + " " + event["env_name"]
                    sns_response = send_sns(sns_subject, sns_output, event["sns_arn"])
                    logger.info("Sending report to {0} - Status {1}".format(event["sns_arn"], sns_response["ResponseMetadata"]["HTTPStatusCode"]))
            else:
                if event['output'] == "S3":
                    sns_output = "Error executing process, error detail in:\n Lambda name: " + context.function_name + "\nLog group: " + context.log_group_name + "\nLog stream: " + context.log_stream_name + "\nRequest id: " + context.aws_request_id
                    write_to_s3(event, sns_output)
                elif event['output'] == "SNS":
                    sns_subject = sns_subject + " " + event["acc_id"] + " " + event["type_id"] + " " + event["env_name"]
                    sns_response = send_sns(sns_subject, "Error executing process, error detail in:\n Lambda name: " + context.function_name + "\nLog group: " + context.log_group_name + "\nLog stream: " + context.log_stream_name + "\nRequest id: " + context.aws_request_id, event["sns_arn"])
                logger.error("No output available")
        else:
            logger.error("Invalid caller: {0} - expecting: collector".format(event['driver']))
    else:
        logger.error("Event Source not supported: {0}".format(event["source"]))
