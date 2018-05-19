# Cloud Insight Vulnerability Notification

Sample architecture that utilize AlertLogic API to collect vulnerability state and notify when vulnerability added or removed. This sample will utilize AWS DynamoDB, Lambda, API Gateway, SNS and S3. You will be charged for AWS resource deployed from this example.

![architecture](docs/architecture.png)

AlertLogic API end-point used in this demonstration:

* Cloud Insight API (https://console.cloudinsight.alertlogic.com/api/#/)

## Requirements
* Alert Logic Account ID (CID)
* Credentials to Alert Logic Cloud Insight (user name and password, or access key and secret key)
* Cloud Insight Deployment in the target CID

## Contributing
This sample will be provided AS IS with no long term support, please provide PR to contribute.

##License and Authors
License:
Distributed under the Apache 2.0 license.

Authors:
Welly Siauw (welly.siauw@alertlogic.com)
