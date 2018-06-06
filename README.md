
# Cloud Insight Vulnerability Notification

Sample architecture that utilize AlertLogic API to collect vulnerability state and notify when vulnerability added or removed. This sample will utilize AWS DynamoDB, Lambda, API Gateway, SNS and S3. You will be charged for AWS resource deployed from this example.

![architecture](docs/architecture.png)

AlertLogic API end-point used in this demonstration:

* Cloud Insight API (https://console.cloudinsight.alertlogic.com/api/#/)

## Requirements
* Alert Logic Account ID (CID)
* Credentials to Alert Logic Cloud Insight (user name and password, or access key and secret key)
* Cloud Insight Deployment in the target CID

## Getting Started
Use the [CFT template](/cloud_formation) to launch the solution. The master stack will launch 4 nested child stack.

The Master lambda function will periodically query DynamoDB table called `CID Map` to find target CID to execute. By default this table will be empty and you need to fill it with CID info.

From the master CFT stack, grab the output `SNS topic` and `S3 bucket` value. The `S3 bucket` will store result from all checks and the `SNS topic` can be use to subscribe to the notification.

From the master CFT stack, grab the output `RegisterURL` and `APIKey`, use AWS CLI or AWS Console to find the API Key value from this API Key ID. Use it to make POST request to register new Customer ID (CID) into `CID Map` table.

### Sample POST:
```
export APIKEY_TOKEN="my_api_key"
export APIKEY_HEADER="X-Api-Key:"
export APIKEY_HEADER+=$APIKEY_TOKEN
curl -X POST -d @payload.json -H "Content-Type: application/json" -H "Accept: application/json" -H $APIKEY_HEADER "https://w5iguju3u0.execute-api.us-east-1.amazonaws.com/prod/register" | jq "."
```

### Sample payload:
```
{
  "id": "my_target_cid",
  "user": "my_cloud_insight_user",
  "password": "my_cloud_insight_user",
  "parent_cid": "2",
  "yarp": "api.cloudinsight.alertlogic.com",
  "output": "S3",
  "sns_arn": "my_target_sns",
  "s3_bucket": "my_target_s3",
  "ttl": "90",
  "filter": {
    "min": "1",
    "max": "10"
  },
  "driver": "register",
  "source": "aws.apigateway"
}
```
### Notification
If you want to receive notification, subscribe to the SNS Topic either via email end points or other prefered method. You can also download the results in text file from the S3 bucket.

### Manual Test
You can create test event on the master lambda function in order to trigger it to run specific events. All events are driven from `[master-stack-name]-ci_rr_master` lambda function. Here are some sample test event that you can generate and invoke manually:

#### Monitor
Trigger the function to scan all Customer ID (CID) and find all Cloud Insight deployment and register it. This is the pre-requisite before further scan/check can run.
```
{
  "source": "aws.event",
  "driver": "monitor",
  "parent_cid": "ALL",
  "log_level": "info"
}
```

#### Collector
Trigger the function to scan all Cloud Insight deployment and record the vulnerability state. There must be at minimum two separate Collector events runs before comparison can be performed. Modify the value for `parent_cid` if you want to trigger collection for specific CID.
```
{
  "source": "aws.event",
  "driver": "collector",
  "parent_cid": "ALL",
  "log_level": "info"
}
```

#### Reporter
Trigger the function to scan all Cloud Insight deployment and compare the vulnerability state from the last 2 Collector runs. There must be at minimum two separate Collector events runs before comparison can be performed. Modify the value for `parent_cid` if you want to trigger comparison for specific CID.
```
{
  "source": "aws.event",
  "driver": "reporter",
  "parent_cid": "ALL",
  "log_level": "info"
}
```

#### Sender
Trigger the function to scan all Cloud Insight deployment and send the comparison result to either S3 or SNS. There must be at minimum one Reporter event runs before Sender can be performed. Modify the value for `parent_cid` if you want to trigger sender for specific CID.
```
{
  "source": "aws.event",
  "driver": "sender",
  "parent_cid": "ALL",
  "log_level": "info"
}
```

## Contributing
This sample will be provided AS IS with no long term support, please provide PR to contribute.

## License and Authors
License:
Distributed under the Apache 2.0 license.

Authors:
Welly Siauw (welly.siauw@alertlogic.com)
