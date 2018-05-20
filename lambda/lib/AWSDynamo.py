from datetime import datetime
import boto3
import json
import logging
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

def prep_item(data):
    #TODO: fix this in the future
    #serialize and deserialized item to decode float to string
    #DynamoDB limit with float: https://github.com/boto/boto3/issues/665
    return json.loads(json.dumps(data, sort_keys=True, default=str, indent=2), parse_float=str)

def create_logger(name, level):
    ## logging.basicConfig() call needs to be called to creating a config first
    ##    http://stackoverflow.com/questions/36410373/no-handlers-could-be-found-for-logger-main
    ##    https://docs.python.org/2/howto/logging.html
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(name)
    logger.setLevel(get_level(level))
    return logger

def get_level(l):
    if l == "debug":
        return logging.DEBUG
    elif l == "info":
        return logging.INFO
    elif l == "warning":
        return logging.WARNING
    else:
        return logging.INFO

class DynamoDBClient():
    def __init__(self, args):
        self.logger = create_logger(__name__, args['log_level'])
        self.logger.debug("Initialize DynamoDB Resource: {0}:{1}".format(args['db_name'], args['db_region']))
        self.dynamodb = boto3.resource('dynamodb', region_name=args['db_region'])
        self.db_table = self.dynamodb.Table(args['db_name'])

    def scan_table(self, select_attribute, filter_expression):
        try:
            response = self.db_table.scan(
                Select=select_attribute,
                FilterExpression=filter_expression
            )
            return response

        except ClientError as e:
            logger.error(e.response['Error']['Message'] + ": " + str(self.db_table))
            return False

    def query_table(self, select_attribute, key_condition, scan_index_forward=True):
        try:
            response = self.db_table.query(
                Select=select_attribute,
                KeyConditionExpression=key_condition,
                ScanIndexForward=scan_index_forward
            )
            return response

        except ClientError as e:
            self.logger.error(e.response['Error']['Message'] + ": " + str(self.db_table))
            return False

    def query_table_with_index(self, select_attribute, key_condition, index_name, projection, attribute_names, scan_index_forward=False):
        try:
            response = self.db_table.query(
                Select=select_attribute,
                KeyConditionExpression=key_condition,
                IndexName=index_name,
                ProjectionExpression=projection,
                ExpressionAttributeNames=attribute_names,
                ScanIndexForward=scan_index_forward
            )
            return response

        except ClientError as e:
            self.logger.error(e.response['Error']['Message'] + ": " + str(self.db_table))
            return False

    #Accept list, write using batch and append date_marker as timestamp
    def write_to_table(self, data, timestamp=None, overwrite_pkeys=None, ttl=None):
        if timestamp == None:
            currenttime = datetime.now()
            timestamp = currenttime.strftime('%Y/%m/%d %H:%M:%S')
        try:
            with self.db_table.batch_writer(overwrite_by_pkeys=overwrite_pkeys) as batch:
                for item in data:
                    item["date_marker"] = timestamp
                    item["TTL"] = ttl
                    batch.put_item(Item=prep_item(item))
            return True

        except ClientError as e:
            self.logger.error(e.response['Error']['Message'] + ": " + str(self.db_table))
            return False

    #Accept single item, write single item
    def single_write_to_table(self, data):
        try:
            response = self.db_table.put_item(Item=prep_item(data))
            return response

        except ClientError as e:
            self.logger.error(e.response['Error']['Message'] + ": " + str(self.db_table))
            return False

    #Update single item
    def single_update_to_table(self, keys, update_expression, attribute_names, attribute_values):
        try:
            response = self.db_table.update_item(
                Key=keys,
                UpdateExpression=update_expression,
                ExpressionAttributeNames=attribute_names,
                ExpressionAttributeValues=attribute_values
            )
            return response

        except ClientError as e:
            self.logger.error(e.response['Error']['Message'] + ": " + str(self.db_table))
            return False

    def single_delete_to_table(self, keys, delete_expression=None, attribute_names=None, attribute_values=None):
        try:
            if delete_expression == None:
                response = self.db_table.delete_item(
                    Key=keys
                )
            else:
                response = self.db_table.delete_item(
                    Key=keys,
                    ConditionExpression=delete_expression,
                    ExpressionAttributeNames=attribute_names,
                    ExpressionAttributeValues=attribute_values
                )
            return response

        except ClientError as e:
            self.logger.error(e.response['Error']['Message'] + ": " + str(self.db_table))
            return False
