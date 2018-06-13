# Cloud Formation to deploy ci_vul_notification

## Quick start
Launch the stack from the provided link:
https://s3-us-west-1.amazonaws.com/al-deployment-services.us-west-1/cloud_formations/ci_rr_launch.yaml

Recommendation: Limit your stack name or project name to 40 characters to avoid issues with resource name restrictions.

## Lambda Invocation Type
For stability and resiliency, use `Event` as the invocation type. All error will be sent over to DLQ, look for resource with logicalID `DeathLetterQueue` in the Lambda stack. In  smaller AWS environment, you can use `RequestResponse` if you want to closely monitor the status.

## Supported Region
Currently this package only available in the following regions:

 - us-east-1
 - us-east-2
 - us-west-1
 - us-west-2
 - eu-central-1
 - eu-west-1
 - eu-west-2
 - eu-west-3
