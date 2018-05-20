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

def calculate_differences(current_data, previous_data, item_key):
    current_list = convert_to_list(current_data, item_key)
    previous_list = convert_to_list(previous_data, item_key)
    added_item = set(current_list) - set(previous_list)
    removed_item = set(previous_list) - set(current_list)
    return added_item, removed_item

def send_sns(sns_subject, sns_message, sns_arn):
    sns_client = boto3.client('sns')
    sns_response = sns_client.publish(
        TargetArn=sns_arn,
        Message=sns_message,
        Subject=sns_subject)
    return sns_response

def create_ttl_time(days):
    return int(time.time()) + (days * 86400)

def write_to_s3(args, payload):
    try:
        date_marker = datetime.strptime(str(args["currentdate"]),'%Y/%m/%d %H:%M:%S')
        filename = str(args["env_name"] + "_" + args["query_type"]) + "_" + str(date_marker.strftime('%Y:%m:%d-%H:%M:%S')) + ".txt"
        s3 = boto3.resource('s3')
        object = s3.Object(args['s3_bucket'], str(args['type_id'] + '/' + str(datetime.now().strftime('%Y-%m-%d')) + '/' + filename))
        object.put(Body=payload.encode())
        return True

    except ClientError as e:
        return False

def output_query_detail(partition_keys, table_partition_key, table_sort_key, table_sort_value, db_table, query_type):
    result = ""
    counter = 1
    for keys in partition_keys:
        item = db_table.query_table(
            "ALL_ATTRIBUTES",
            Key(table_partition_key).eq(keys) & Key(table_sort_key).eq(table_sort_value)
        )
        if item:
            if query_type == "vulnerability":
                result = result + str(counter) + ". " +  str(item["Items"][0]["key"]) + " - name: " +  str(item["Items"][0]["name"]) + " - threat score: " + str(item["Items"][0]["threat_score"]) + "\n"
            elif query_type == "exposure":
                result = result + str(counter) + ". " +  str(item["Items"][0]["name"]) + " - threat score: " + str(item["Items"][0]["threat_score"]) + " - assets: " + str(item["Items"][0]["count"]) + "\n"
            elif query_type == "remediations":
                result = result + str(counter) + ". " +  str(item["Items"][0]["name"]) + " - vul exposure: " + str(len(item["Items"][0]["vulnerabilities"]))  + " - assets: " + str(item["Items"][0]["asset_count"]) + "\n"
            counter += 1

    return result

def report_findings(args, db_table, index_name, index_partition_key, index_partition_value, index_sort_key, index_sort_max_value, index_sort_min_value, table_partition_key, table_sort_key):
    try:
        sns_output = ""
        current_response = db_table.query_table_with_index(
            "SPECIFIC_ATTRIBUTES",
            Key(index_partition_key).eq(index_partition_value) & Key(index_sort_key).eq(index_sort_max_value),
            index_name,
            "#a",
            {"#a" : table_partition_key},
            False
        )
        previous_response = db_table.query_table_with_index(
            "SPECIFIC_ATTRIBUTES",
            Key(index_partition_key).eq(index_partition_value) & Key(index_sort_key).eq(index_sort_min_value),
            index_name,
            "#a",
            {"#a" : table_partition_key},
            False
        )

        if current_response and previous_response:
            added_item, removed_item = calculate_differences(current_response["Items"], previous_response["Items"], table_partition_key)

            logger.info("Acc ID: {0} - Env Name: {1} - CID : {2} - Env ID: {3} \n".format( args['type_id'], args['env_name'], args['acc_id'],  args['env_id']))
            sns_output = sns_output + "Acc ID: {0} - Env Name: {1} - CID : {2} - Env ID: {3} \n".format( args['type_id'], args['env_name'], args['acc_id'],  args['env_id'])

            #EXPERIMENTAL TO PUT RESULTANT IN TABLE FOR LOOKUP QUERY
            if args['query_type'] == "vulnerability":
                args['db_name'] = args['db_name_add_prep']
                myAddedPrepTable = AWSDynamo.DynamoDBClient(args)
                counter = add_finding_to_prep(added_item, table_partition_key, table_sort_key, args["currentdate"], db_table, args, myAddedPrepTable)
                logger.info("Added {0} vulnerabilities to prep table".format(counter))

                args['db_name'] = args['db_name_rmv_prep']
                myRemovedPrepTable = AWSDynamo.DynamoDBClient(args)
                counter = add_finding_to_prep(removed_item, table_partition_key, table_sort_key, args["previousdate"], db_table, args, myRemovedPrepTable)
                logger.info("Removed {0} vulnerabilities to prep table".format(counter))

            logger.info("Current date: {0} - Total {1}: {2}".format(args["currentdate"], args["query_type"], current_response["Count"]))
            logger.info("Previous date: {0} - Total {1}: {2}".format(args["previousdate"], args["query_type"], previous_response["Count"]))
            sns_output = sns_output + "Current date: {0} - Total {1}: {2}\n".format(args["currentdate"], args["query_type"], current_response["Count"])
            sns_output = sns_output + "Previous date: {0} - Total {1}: {2}\n".format(args["previousdate"], args["query_type"], previous_response["Count"])


            if args['query_type'] == 'exposure':
                added_item = output_query_detail(added_item, table_partition_key, table_sort_key, args["env_id"] + "/" + args["currentdate"] , db_table, args["query_type"])
            else:
                added_item = output_query_detail(added_item, table_partition_key, table_sort_key, args["currentdate"], db_table, args["query_type"])
            #logger.info("New {0} added:".format(args["query_type"]))
            #logger.info(added_item)
            sns_output = sns_output + "\nNew {0} added:\n".format(args["query_type"])
            sns_output = sns_output + added_item

            if args['query_type'] == 'exposure':
                removed_item = output_query_detail(removed_item, table_partition_key, table_sort_key, args["env_id"] + "/" + args["previousdate"], db_table, args["query_type"])
            else:
                removed_item = output_query_detail(removed_item, table_partition_key, table_sort_key, args["previousdate"], db_table, args["query_type"])
            #logger.info("Existing {0} removed:".format(args["query_type"]))
            #logger.info(removed_item)
            sns_output = sns_output + "\nExisting {0} removed:\n".format(args["query_type"])
            sns_output = sns_output + removed_item


        return sns_output

    except ClientError as e:
        logger.error(e.response['Error']['Message'] + ": " + str(self.db_table))
        return None

def add_finding_to_prep(partition_keys, table_partition_key, table_sort_key, table_sort_value, db_table, args, prep_table):
    item_payload = []
    sort_key = args['env_id'] + "/" + args['currentdate']
    counter = 0
    for keys in partition_keys:
        item = db_table.query_table(
            "ALL_ATTRIBUTES",
            Key(table_partition_key).eq(keys) & Key(table_sort_key).eq(table_sort_value)
        )
        table_key = {}
        table_key['vulnerability_id'] = item["Items"][0]['vulnerability_id']
        table_key['vul_key_sort_key'] = sort_key
        update_expression = "SET #VUL_ITEMS = list_append(if_not_exists(#VUL_ITEMS, :EMPTY_LIST), :VUL_VALUES)" \
                            ", #ENV_ID = :ENV_VAL" \
                            ", #DATE_MARKER = :DATE" \
                            ", #TIME_TO_LIVE = :TTL"
        attribute_names = {"#VUL_ITEMS": "vulnerability_items", "#ENV_ID": "deployment_id", "#DATE_MARKER" : "date_marker", "#TIME_TO_LIVE" : "TTL"}
        attribute_values = {":VUL_VALUES": [item["Items"][0]['key']], ":EMPTY_LIST" : [], ":ENV_VAL": args["env_id"], ":DATE": args['currentdate'], ":TTL": create_ttl_time(int(args["ttl"]))}
        prep_table.single_update_to_table(table_key, update_expression, attribute_names, attribute_values)
        counter += 1
    return counter

def lambda_handler(event, context):
    if event["source"] == "driver-reporter" :
        if event['driver'] == "reporter":
            myDynamoTable = AWSDynamo.DynamoDBClient(event)
            logger.info("Start Operations : {0} - Event Type: {1}".format(datetime.now(), event['query_type']))
            sns_output = ""
            sns_subject = ""
            if event['query_type'] == "remediations":
                sns_output = report_findings(event, myDynamoTable, event["index_name"], "deployment_id", event["env_id"], "date_marker", event["currentdate"], event["previousdate"], "key", "date_marker")
                sns_subject = "CI Remediation "

            elif event['query_type'] == "exposure":
                sns_output = report_findings(event, myDynamoTable, event["index_name"], "deployment_id", event["env_id"], "date_marker", event["currentdate"], event["previousdate"], "vulnerability_id", "vul_map_sort_key")
                sns_subject = "CI Vul Exposure "

            elif event['query_type'] == "vulnerability":
                sns_output = report_findings(event, myDynamoTable, event["index_name"], "deployment_id", event["env_id"], "date_marker", event["currentdate"], event["previousdate"], "key", "date_marker")
                sns_subject = "CI Vulnerabilities "

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
