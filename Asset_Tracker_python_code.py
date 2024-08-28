import argparse
from datetime import datetime
import boto3
import json
import zipfile
import io
import time
import requests
from botocore.exceptions import ClientError

# Initialize the IoT client
session = boto3.Session(region_name='us-east-1')
lambda_client = session.client('lambda')
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
apigateway_client = boto3.client('apigateway')
iam_client = session.client('iam')
iot_client = session.client('iot')
YOUR_REGION = 'us-east-1'
YOUR_ACCOUNT_ID = '079921713039'
s3_client = session.client('s3')


def create_thing(thing_name):
    try:
        response = iot_client.create_thing(
            thingName=thing_name
        )
        print("Thing created:", response)
        return response['thingArn']
    except Exception as e:
        print("Error creating thing:", e)
        return None


def create_policy(policy_name, policy_document):
    try:
        response = iot_client.create_policy(
            policyName=policy_name,
            policyDocument=json.dumps(policy_document)
        )
        print("Policy created:", response)
        return response['policyArn']
    except Exception as e:
        print("Error creating policy:", e)
        return None


def create_certificate_and_store_in_s3(Registration_id):
    # bucket_name = f'{Registration_id}-certificates-bucket'
    try:
        # Create the keys and certificate
        response = iot_client.create_keys_and_certificate(setAsActive=True)
        print("Certificate created:", response)

        certificate_arn = response['certificateArn']
        certificate_pem = response['certificatePem']
        key_pair = response['keyPair']

        response = iot_client.describe_endpoint(endpointType='iot:Data-ATS')
        iot_endpoint = response['endpointAddress']

        ca_url = "https://www.amazontrust.com/repository/AmazonRootCA1.pem"
        response = requests.get(ca_url)
        ca_certificate = response.content.decode('utf-8')

        data = {
            'Car_ID': Registration_id,
            'THINGNAME': Registration_id + "Thing",
            'Device_Status_Topic': f'iot/{Registration_id}ds',
            'Rfid_Status_Topic': f'iot/{Registration_id}rs',
            'Live_Tracking_Topic': f'iot/{Registration_id}lt',
            'AWSENDPOINT': iot_endpoint,
            'AWS_CERT_CA': ca_certificate,
            'AWS_CERT_CRT': certificate_pem,
            'AWS_CERT_PRIVATE': key_pair['PrivateKey']
        }

        with open(f'{Registration_id}-config.json', 'w') as json_file:
            json.dump(data, json_file, indent=4)

        print("IoT endpoint and CA certificate saved to iot_config.json")

        return certificate_arn, certificate_pem, key_pair
        # return None
    except Exception as e:
        print("Error creating certificate or storing in S3:", e)
        return None, None, None, None


def attach_policy_to_certificate(policy_name, certificate_arn):
    try:
        response = iot_client.attach_policy(
            policyName=policy_name,
            target=certificate_arn
        )
        print("Policy attached to certificate:", response)
    except Exception as e:
        print("Error attaching policy to certificate:", e)


def attach_thing_to_certificate(thing_name, certificate_arn):
    try:
        response = iot_client.attach_thing_principal(
            thingName=thing_name,
            principal=certificate_arn
        )
        print("Thing attached to certificate:", response)
    except Exception as e:
        print("Error attaching thing to certificate:", e)


def live_tracking(Registration_id):
    bucket_name = f'{Registration_id}-live-tracker'
    role_name = f'{bucket_name}-s3role'
    policy_name = f'{bucket_name}_HeadBucketPolicy'

    # Function to check if a bucket exists
    def bucket_exists(bucket_name_arg):
        try:
            s3_client.head_bucket(Bucket=bucket_name_arg)
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                return False
            elif error_code == '403':
                print(f"Access to bucket {bucket_name_arg} is forbidden. Check your permissions.")
                return True
            else:
                raise e

    # Create IAM Role
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "iot.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        role = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
        )
        print(f"IAM Role {role_name} created!")
    except ClientError as e:
        print(f"Error creating IAM role: {e}")
        role = None

    # Attach Policy to Role
    policy = None
    if role:
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:HeadBucket",
                    "Resource": f"arn:aws:s3:::{bucket_name}"
                }
            ]
        }

        try:
            policy = iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy['Policy']['Arn']
            )
            print(f"Policy {policy_name} attached to role {role_name}")
        except ClientError as e:
            print(f"Error creating or attaching policy: {e}")

    # Create S3 Bucket if it doesn't exist
    original_bucket_name = bucket_name
    while bucket_exists(bucket_name):
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        bucket_name = f"{original_bucket_name}-{timestamp}"
        print(f"Bucket name {original_bucket_name} already exists. Trying with new name: {bucket_name}")

    try:
        s3_client.create_bucket(Bucket=bucket_name)
        print(f"S3 bucket {bucket_name} created successfully.")
    except ClientError as e:
        print(f"Error creating S3 bucket: {e}")
        # Delete the IAM role and policy if bucket creation fails
        if role:
            try:
                if policy:
                    iam_client.detach_role_policy(
                        RoleName=role_name,
                        PolicyArn=policy['Policy']['Arn']
                    )
                    iam_client.delete_policy(PolicyArn=policy['Policy']['Arn'])
                    print(f"Policy {policy_name} deleted due to bucket creation failure.")
                iam_client.delete_role(RoleName=role_name)
                print(f"IAM Role {role_name} deleted due to bucket creation failure.")
            except ClientError as delete_error:
                print(f"Error deleting IAM role or policy: {delete_error}")

    role_name = f"{Registration_id}-role"

    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "iot.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    # Create the role
    role = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
    )

    # Define the inline policy
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*"
            }
        ]
    }

    # Attach the inline policy to the role
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName="S3PutObjectPolicy",
        PolicyDocument=json.dumps(inline_policy)
    )

    print("Role created and policy attached successfully.")

    # Define the rule
    rule_name = f'{Registration_id}_livetracking_rule'
    sql_statement = f"SELECT * FROM 'iot/{Registration_id}lt'"
    # s3_client.put_object(Bucket=f'{Registration_id}-certificates-bucket', Key='data/live-tracking-topic.txt',
    #                      Body=f'iot/{Registration_id}lt')

    actions = [
        {
            's3': {
                'bucketName': bucket_name,
                'key': 'livekey',
                'roleArn': role['Role']['Arn'],
                'cannedAcl': 'private'
            }
        }
    ]
    time.sleep(10)
    # Create the rule
    response = iot_client.create_topic_rule(
        ruleName=rule_name,
        topicRulePayload={
            'sql': sql_statement,
            'actions': actions,
            'ruleDisabled': False
        }
    )
    print(f"Iot Rule {rule_name} created successfully")
    # print(response)
    lambda_function_name = f'{Registration_id}-livetracking-lambda-function'
    lambda_code = f"""
import json
import boto3
from botocore.exceptions import ClientError

s3 = boto3.client('s3')

def lambda_handler(event, context):
    try:
        response = s3.get_object(Bucket='{bucket_name}', Key='livekey')""" + """
        content = response['Body'].read().decode('utf-8')
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps(content)
        }
    except ClientError as e:
        error_message = e.response['Error']['Message']
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps({'error': error_message})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': json.dumps({'error': str(e)})
        }
"""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr('lambda_function.py', lambda_code)
    zip_buffer.seek(0)

    # Create IAM Role for Lambda

    role_name = f'{Registration_id}-IoTLambdaExecutionRole'
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        role = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
        )
        print(f"IAM Role {role_name} created!")
        role_arn = role['Role']['Arn']
    except iam_client.exceptions.EntityAlreadyExistsException:
        role = iam_client.get_role(RoleName=role_name)
        print(f"IAM Role {role_name} already exists.")
        role_arn = role['Role']['Arn']

    # Attach basic execution policy to the role
    policy_arn = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=policy_arn
    )

    # Attach S3 read access policy to the role
    s3_read_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:Get*",
                    "s3:List*",
                    "s3:Describe*",
                    "s3-object-lambda:Get*",
                    "s3-object-lambda:List*"
                ],
                "Resource": "*"
            }
        ]
    }

    s3_read_policy = iam_client.create_policy(
        PolicyName=f'{Registration_id}S3ReadAccessPolicy',
        PolicyDocument=json.dumps(s3_read_policy_document)
    )

    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=s3_read_policy['Policy']['Arn']
    )

    # Wait for role propagation
    time.sleep(10)

    # Create the Lambda function
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr('lambda_function.py', lambda_code)
    zip_buffer.seek(0)

    response = lambda_client.create_function(
        FunctionName=lambda_function_name,
        Runtime='python3.12',
        Role=role_arn,
        Handler='lambda_function.lambda_handler',
        Code={'ZipFile': zip_buffer.read()},
        Timeout=15,
        MemorySize=128,
        Publish=True
    )
    print(f"Lambda function {lambda_function_name} created!")
    lambda_arn = response['FunctionArn']


# Device status function
def device_status(Registration_id):
    bucket_name = f'{Registration_id}-device-status'
    role_name = f'{bucket_name}-devicestatus-s3role'
    policy_name = f'{bucket_name}_devicestatus-s3HeadBucketPolicy'

    # Function to check if a bucket exists
    def bucket_exists(bucket_name_arg):
        try:
            s3_client.head_bucket(Bucket=bucket_name_arg)
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                return False
            elif error_code == '403':
                print(f"Access to bucket {bucket_name_arg} is forbidden. Check your permissions.")
                return True
            else:
                raise e

    # Create IAM Role
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "iot.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        role = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
        )
        print(f"IAM Role {role_name} created!")
    except ClientError as e:
        print(f"Error creating IAM role: {e}")
        role = None

    # Attach Policy to Role
    policy = None
    if role:
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:HeadBucket",
                    "Resource": f"arn:aws:s3:::{bucket_name}"
                }
            ]
        }

        try:
            policy = iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy['Policy']['Arn']
            )
            print(f"Policy {policy_name} attached to role {role_name}")
        except ClientError as e:
            print(f"Error creating or attaching policy: {e}")

    # Create S3 Bucket if it doesn't exist
    original_bucket_name = bucket_name
    while bucket_exists(bucket_name):
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        bucket_name = f"{original_bucket_name}-{timestamp}"
        print(f"Bucket name {original_bucket_name} already exists. Trying with new name: {bucket_name}")

    try:
        s3_client.create_bucket(Bucket=bucket_name)
        print(f"S3 bucket {bucket_name} created successfully.")
    except ClientError as e:
        print(f"Error creating S3 bucket: {e}")
        # Delete the IAM role and policy if bucket creation fails
        if role:
            try:
                if policy:
                    iam_client.detach_role_policy(
                        RoleName=role_name,
                        PolicyArn=policy['Policy']['Arn']
                    )
                    iam_client.delete_policy(PolicyArn=policy['Policy']['Arn'])
                    print(f"Policy {policy_name} deleted due to bucket creation failure.")
                iam_client.delete_role(RoleName=role_name)
                print(f"IAM Role {role_name} deleted due to bucket creation failure.")
            except ClientError as delete_error:
                print(f"Error deleting IAM role or policy: {delete_error}")

    role_name = f"{Registration_id}-iot-to-s3-role"

    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "iot.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    # Create the role
    role = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
    )

    # Define the inline policy
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*"
            }
        ]
    }

    # Attach the inline policy to the role
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName="devicestatus-S3PutObjectPolicy",
        PolicyDocument=json.dumps(inline_policy)
    )

    print("Role created and policy attached successfully.")

    # Define the rule
    rule_name = f'{Registration_id}_devicestatus_rule'
    sql_statement = f"SELECT * FROM 'iot/{Registration_id}ds'"
    # s3_client.put_object(Bucket=f'{Registration_id}-certificates-bucket', Key='data/device-status-topic.txt',
    #                      Body=f'iot/{Registration_id}ds')

    actions = [
        {
            's3': {
                'bucketName': bucket_name,
                'key': 'devicestatus',
                'roleArn': role['Role']['Arn'],
                'cannedAcl': 'private'
            }
        }
    ]
    time.sleep(10)
    # Create the rule
    response = iot_client.create_topic_rule(
        ruleName=rule_name,
        topicRulePayload={
            'sql': sql_statement,
            'actions': actions,
            'ruleDisabled': False
        }
    )
    print(f"Iot Rule {rule_name} created successfully")
    # print(response)
    lambda_function_name = f'{Registration_id}-devicestatus-lambda-function'
    lambda_code = f"""
import json
import boto3

s3 = boto3.client('s3')

def lambda_handler(event, context):
        # TODO implement
        response = s3.get_object(Bucket='{bucket_name}', Key='devicestatus')""" + """
        content = response['Body'].read().decode('utf-8')
        return {
                'statusCode': 200,
                'headers': {
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
                },
                'body': json.dumps(content)
            }"""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr('lambda_function.py', lambda_code)
    zip_buffer.seek(0)

    # Create IAM Role for Lambda

    role_name = f'{Registration_id}-devicestatus-IoTLambdaExecutionRole'
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        role = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
        )
        print(f"IAM Role {role_name} created!")
        role_arn = role['Role']['Arn']
    except iam_client.exceptions.EntityAlreadyExistsException:
        role = iam_client.get_role(RoleName=role_name)
        print(f"IAM Role {role_name} already exists.")
        role_arn = role['Role']['Arn']

    # Attach basic execution policy to the role
    policy_arn = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=policy_arn
    )

    # Attach S3 read access policy to the role
    s3_read_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:Get*",
                    "s3:List*",
                    "s3:Describe*",
                    "s3-object-lambda:Get*",
                    "s3-object-lambda:List*"
                ],
                "Resource": "*"
            }
        ]
    }

    s3_read_policy = iam_client.create_policy(
        PolicyName=f'{Registration_id}-devicestatus-S3ReadAccessPolicy',
        PolicyDocument=json.dumps(s3_read_policy_document)
    )

    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=s3_read_policy['Policy']['Arn']
    )

    # Wait for role propagation
    time.sleep(10)

    # Create the Lambda function
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr('lambda_function.py', lambda_code)
    zip_buffer.seek(0)

    response = lambda_client.create_function(
        FunctionName=lambda_function_name,
        Runtime='python3.12',
        Role=role_arn,
        Handler='lambda_function.lambda_handler',
        Code={'ZipFile': zip_buffer.read()},
        Timeout=15,
        MemorySize=128,
        Publish=True
    )
    print(f"Lambda function {lambda_function_name} created!")
    lambda_arn = response['FunctionArn']


def rfid_status(Registration_id):
    dynamodb_client = boto3.client('dynamodb')

    table_name = f'{Registration_id}Rfid_table'
    response = dynamodb_client.create_table(
        TableName=table_name,
        KeySchema=[
            {'AttributeName': 'id', 'KeyType': 'HASH'}
        ],
        AttributeDefinitions=[
            {'AttributeName': 'id', 'AttributeType': 'S'}
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )

    print(f"Created DynamoDB table: {table_name}")

    bucket_name = f'{Registration_id}-rfidstatus'
    role_name = f'{bucket_name}-rfidstatus-s3role'
    policy_name = f'{bucket_name}_rfidstatus-s3HeadBucketPolicy'

    # Function to check if a bucket exists
    def bucket_exists(bucket_name_arg):
        try:
            s3_client.head_bucket(Bucket=bucket_name_arg)
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                return False
            elif error_code == '403':
                print(f"Access to bucket {bucket_name_arg} is forbidden. Check your permissions.")
                return True
            else:
                raise e

    # Create IAM Role
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "iot.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        role = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
        )
        print(f"IAM Role {role_name} created!")
    except ClientError as e:
        print(f"Error creating IAM role: {e}")
        role = None

    # Attach Policy to Role
    policy = None
    if role:
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:HeadBucket",
                    "Resource": f"arn:aws:s3:::{bucket_name}"
                }
            ]
        }

        try:
            policy = iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy['Policy']['Arn']
            )
            print(f"Policy {policy_name} attached to role {role_name}")
        except ClientError as e:
            print(f"Error creating or attaching policy: {e}")

    # Create S3 Bucket if it doesn't exist
    original_bucket_name = bucket_name
    while bucket_exists(bucket_name):
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        bucket_name = f"{original_bucket_name}-{timestamp}"
        print(f"Bucket name {original_bucket_name} already exists. Trying with new name: {bucket_name}")

    try:
        s3_client.create_bucket(Bucket=bucket_name)
        print(f"S3 bucket {bucket_name} created successfully.")
    except ClientError as e:
        print(f"Error creating S3 bucket: {e}")
        # Delete the IAM role and policy if bucket creation fails
        if role:
            try:
                if policy:
                    iam_client.detach_role_policy(
                        RoleName=role_name,
                        PolicyArn=policy['Policy']['Arn']
                    )
                    iam_client.delete_policy(PolicyArn=policy['Policy']['Arn'])
                    print(f"Policy {policy_name} deleted due to bucket creation failure.")
                iam_client.delete_role(RoleName=role_name)
                print(f"IAM Role {role_name} deleted due to bucket creation failure.")
            except ClientError as delete_error:
                print(f"Error deleting IAM role or policy: {delete_error}")

    lambda_function_name = f'{Registration_id}-saveToRfidTable'
    lambda_code = f"""
import json
import boto3
from botocore.exceptions import ClientError
from decimal import Decimal
import time
from boto3.dynamodb.conditions import Attr
from datetime import datetime, date, time, timedelta

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('{table_name}')
s3 = boto3.client('s3')
bucket_name = '{bucket_name}'""" + """


def lambda_handler(event, context):
    try:
        
        vehicle_id = event['Car_ID']
        Rfid = event['Rfid']
        timestamp = event['timestamp']
        latitude = f"{event['latitude']}"
        longitude = f"{event['longitude']}"
        speed = f"{event['speed']}"
        partition_key = f"{vehicle_id}_{timestamp}"
        
        if vehicle_id is None or timestamp is None or latitude is None or longitude is None or speed is None:
            raise ValueError("Missing required data in the payload")
        
        else:
            response = table.scan(FilterExpression=Attr('Rfid').eq(Rfid))

            if 'Items' in response and len(response['Items']) > 0:
                # vehicle_id = "response1"
                if len(response['Items']) % 2 == 1:
                    t1 = datetime.strptime(response['Items'][0]['timestamp'], "%Y-%m-%d %H:%M:%S")
                    t2 = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                    timevalue = t2 - t1
                    # vehicle_id = str(timevalue)
                    time_str = '0:00:05'
                    time_obj = datetime.strptime(time_str, "%H:%M:%S").time()
                    second_5 = timedelta(hours=time_obj.hour, minutes=time_obj.minute, seconds=time_obj.second)
                    
                    if timevalue >= second_5:
                        print("absent case")
                        response = table.put_item(
                             Item={
                                 'id': partition_key,
                                 'Rfid':Rfid.lower(),
                                 'vehicle_reg': vehicle_id,
                                 'timestamp': timestamp,  # Ensure timestamp is an integer
                                 'latitude': Decimal(latitude),
                                 'longitude': Decimal(longitude),
                                 'speed': Decimal(speed),
                                 'Rfid_status': 'OUT'
                             })
                        
                        key = f'{Rfid.lower()}.txt'
                        data = {
                                 'id': partition_key,
                                 'Rfid':Rfid.lower(),
                                 'vehicle_reg': vehicle_id,
                                 'timestamp': timestamp,  # Ensure timestamp is an integer
                                 'latitude': Decimal(latitude),
                                 'longitude': Decimal(longitude),
                                 'speed': Decimal(speed),
                                 'Rfid_status': 'OUT'
                             }
                        json_data = json.dumps(data, default=str)
                        s3.put_object(Bucket=bucket_name, Key=key, Body=json_data)
                        vehicle_id1 = 'odd case'
                        return vehicle_id1
                        
                elif len(response['Items']) % 2 == 0:
                    t1 = datetime.strptime(response['Items'][0]['timestamp'], "%Y-%m-%d %H:%M:%S")
                    t2 = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                    timevalue = t2 - t1
                    time_str = '0:00:05'
                    time_obj = datetime.strptime(time_str, "%H:%M:%S").time()
                    second_5 = timedelta(hours=time_obj.hour, minutes=time_obj.minute, seconds=time_obj.second)
                    if timevalue >= second_5:
                        print('present')
                        response = table.put_item(
                            Item={
                                 'id': partition_key,
                                 'vehicle_reg': vehicle_id,
                                 'Rfid':Rfid.lower(),
                                 'timestamp': timestamp,  # Ensure timestamp is an integer
                                 'latitude': Decimal(latitude),
                                 'longitude': Decimal(longitude),
                                 'speed': Decimal(speed),
                                 'Rfid_status': 'IN'
                             })
                        key = f'{Rfid.lower()}.txt'
                        data1 = {
                                 'id': partition_key,
                                 'vehicle_reg': vehicle_id,
                                 'Rfid':Rfid.lower(),
                                 'timestamp': timestamp,  # Ensure timestamp is an integer
                                 'latitude': Decimal(latitude),
                                 'longitude': Decimal(longitude),
                                 'speed': Decimal(speed),
                                 'Rfid_status': 'IN'
                             }
                        json_data = json.dumps(data1, default=str)
                        s3.put_object(Bucket=bucket_name, Key=key, Body=json_data)
                        vehicle_id1 = 'even case'
                        return vehicle_id1
                        
            else:
                response = table.put_item(
                    Item={
                        'id': partition_key,
                        'Rfid':Rfid.lower(),
                        'vehicle_reg': vehicle_id,
                        'timestamp': timestamp,  # Ensure timestamp is an integer
                        'latitude': Decimal(latitude),
                        'longitude': Decimal(longitude),
                        'speed': Decimal(speed),
                        'Rfid_status': 'IN'
                    })
                    
                key = f'{Rfid.lower()}.txt'
                data2 = {
                        'id': partition_key,
                        'Rfid':Rfid.lower(),
                        'vehicle_reg': vehicle_id,
                        'timestamp': timestamp,  # Ensure timestamp is an integer
                        'latitude': Decimal(latitude),
                        'longitude': Decimal(longitude),
                        'speed': Decimal(speed),
                        'Rfid_status': 'IN'
                    }
                json_data = json.dumps(data2, default=str)
                s3.put_object(Bucket=bucket_name, Key=key, Body=json_data)
                
                vehicle_id1 = 'first entry'
                return vehicle_id1
                
    except ClientError as e:
        print(f"Failed to insert data into DynamoDB: {e.response['Error']['Message']}")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

"""

    # Create IAM Role for Lambda

    role_name = f'{Registration_id}-rfidstatus-IoTLambdaExecutionRole'
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        role = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
        )
        print(f"IAM Role {role_name} created!")
        role_arn = role['Role']['Arn']
    except iam_client.exceptions.EntityAlreadyExistsException:
        role = iam_client.get_role(RoleName=role_name)
        print(f"IAM Role {role_name} already exists.")
        role_arn = role['Role']['Arn']

    # Attach basic execution policy to the role
    policy_arn = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=policy_arn
    )

    # Attach S3 full access policy to the role
    s3_full_access_policy_arn = 'arn:aws:iam::aws:policy/AmazonS3FullAccess'
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=s3_full_access_policy_arn
    )
    # Attach Dynamodb full access policy to the role
    dynamodb_full_access_policy_arn = 'arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess'
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=dynamodb_full_access_policy_arn
    )

    # Wait for role propagation
    time.sleep(10)

    # Create the Lambda function
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr('lambda_function.py', lambda_code)
    zip_buffer.seek(0)

    response = lambda_client.create_function(
        FunctionName=lambda_function_name,
        Runtime='python3.12',
        Role=role_arn,
        Handler='lambda_function.lambda_handler',
        Code={'ZipFile': zip_buffer.read()},
        Timeout=15,
        MemorySize=128,
        Publish=True
    )
    print(f"Lambda function {lambda_function_name} created!")
    lambda_arn = response['FunctionArn']

    role_name = f"{Registration_id}-rfidstatus-iotrule-lambda"

    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "iot.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    # Create the role
    role = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
    )

    # Define the inline policy
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "cloudformation:DescribeStacks",
                    "cloudformation:ListStackResources",
                    "cloudwatch:ListMetrics",
                    "cloudwatch:GetMetricData",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeVpcs",
                    "kms:ListAliases",
                    "iam:GetPolicy",
                    "iam:GetPolicyVersion",
                    "iam:GetRole",
                    "iam:GetRolePolicy",
                    "iam:ListAttachedRolePolicies",
                    "iam:ListRolePolicies",
                    "iam:ListRoles",
                    "lambda:*",
                    "logs:DescribeLogGroups",
                    "states:DescribeStateMachine",
                    "states:ListStateMachines",
                    "tag:GetResources",
                    "xray:GetTraceSummaries",
                    "xray:BatchGetTraces"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "iam:PassedToService": "lambda.amazonaws.com"
                    }
                }
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:DescribeLogStreams",
                    "logs:GetLogEvents",
                    "logs:FilterLogEvents"
                ],
                "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/*"
            }
        ]
    }

    # Attach the inline policy to the role
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName="rfidstatus-S3PutObjectPolicy",
        PolicyDocument=json.dumps(inline_policy)
    )

    print("Role created and policy attached successfully.")

    # Define the rule
    rule_name = f'{Registration_id}_rfidstatus_rule'
    sql_statement = f"SELECT * FROM 'iot/{Registration_id}rs'"
    # s3_client.put_object(Bucket=f'{Registration_id}-certificates-bucket', Key='data/rfid-status-topic.txt',
    #                      Body=f'iot/{Registration_id}rs')
    actions = [
        {
            'lambda': {
                'functionArn': lambda_arn
            }
        }
    ]
    time.sleep(10)
    # Create the rule
    response = iot_client.create_topic_rule(
        ruleName=rule_name,
        topicRulePayload={
            'sql': sql_statement,
            'actions': actions,
            'ruleDisabled': False
        }
    )
    print(f"Iot Rule {rule_name} created successfully")
    # print(response)
    lambda_client.add_permission(
        FunctionName=f'{lambda_function_name}',
        StatementId='IoTInvokePermission',
        Action='lambda:InvokeFunction',
        Principal='iot.amazonaws.com',
        SourceArn=f'arn:aws:iot:us-east-1:079921713039:rule/{rule_name}'
    )

    lambda_function_name = f'{Registration_id}-rfidstatus-lambda-function'
    lambda_code = f"""
import json
import boto3
from datetime import datetime
from decimal import Decimal
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.conditions import Attr

client = boto3.resource('dynamodb')

def get_filtered_items(Rfid, timestamp):
    item_str = ''
    data = client.Table('{Registration_id}Rfid_table')"""+"""
    timestamp1 = timestamp.split(' ')[0]
    response = data.scan(FilterExpression=Attr('timestamp').contains(timestamp1))
    # response = data.scan(FilterExpression=Attr('Rfid').eq(Rfid) or Attr('timestamp').contains(timestamp))
    items = []
    for item in response['Items']:
        if item['Rfid'] == Rfid:
            # Convert to datetime object
            datetime_obj = datetime.strptime(item['timestamp'], '%Y-%m-%d %H:%M:%S')
            timestamp = datetime.strptime(str(timestamp), '%Y-%m-%d %H:%M:%S')
            if str(datetime_obj) == str(timestamp):
                # items.append(item)
                return str(item)
                # break
                # print(items[0])
            elif str(datetime_obj) > str(timestamp):
                return str(item)
            else:
                return "No data found"

def lambda_handler(event, context):
    query_params = event.get('queryStringParameters', {})
    Rfid = query_params.get('Rfid')
    timestamp = query_params.get('timestamp')
    content = get_filtered_items(Rfid, timestamp)
    # TODO implement
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        'body': json.dumps(content)
    }


"""

    # Create IAM Role for Lambda
    role_name = f'{Registration_id}-rfidstatus-IoTLambdaExecutionRole'
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        role = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
        )
        print(f"IAM Role {role_name} created!")
        role_arn = role['Role']['Arn']
    except iam_client.exceptions.EntityAlreadyExistsException:
        role = iam_client.get_role(RoleName=role_name)
        print(f"IAM Role {role_name} already exists.")
        role_arn = role['Role']['Arn']

    # Attach basic execution policy to the role
    policy_arn = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=policy_arn
    )

    #     # Attach S3 read access policy to the role
    s3_full_access_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }
        ]
    }

    s3_fullaccess_policy = iam_client.create_policy(
        PolicyName=f'{Registration_id}-rfidstatus-S3ReadAccessPolicy',
        PolicyDocument=json.dumps(s3_full_access_policy_document)
    )

    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=s3_fullaccess_policy['Policy']['Arn']
    )

    # Wait for role propagation
    time.sleep(10)
    #
    # Create the Lambda function
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr('lambda_function.py', lambda_code)
    zip_buffer.seek(0)
    #
    response = lambda_client.create_function(
        FunctionName=lambda_function_name,
        Runtime='python3.12',
        Role=role_arn,
        Handler='lambda_function.lambda_handler',
        Code={'ZipFile': zip_buffer.read()},
        Timeout=15,
        MemorySize=128,
        Publish=True
    )
    print(f"Lambda function {lambda_function_name} created!")
    lambda_arn = response['FunctionArn']
    #
    lambda_arn = f"arn:aws:lambda:us-east-1:079921713039:function:{Registration_id}-livetracking-lambda-function"

    # Create a new REST API
    api_response = apigateway_client.create_rest_api(
        name='Ats-api',
        description='This is my API'
    )
    api_id = api_response['id']

    # Get the root resource ID
    resources = apigateway_client.get_resources(restApiId=api_id)
    root_id = next(item['id'] for item in resources['items'] if item['path'] == '/')

    # Create resources
    resource_names = ['liveTracking', 'rfidstatus', 'devicestatus']
    resource_ids = {}

    for resource_name in resource_names:
        resource_response = apigateway_client.create_resource(
            restApiId=api_id,
            parentId=root_id,
            pathPart=resource_name
        )
        resource_ids[resource_name] = resource_response['id']

    # Define Lambda ARNs for each resource
    lambda_arns = {
        'liveTracking': f'arn:aws:lambda:{YOUR_REGION}:{YOUR_ACCOUNT_ID}:function:{Registration_id}-livetracking-lambda-function',
        'rfidstatus': f'arn:aws:lambda:{YOUR_REGION}:{YOUR_ACCOUNT_ID}:function:{Registration_id}-rfidstatus-lambda-function',
        'devicestatus': f'arn:aws:lambda:{YOUR_REGION}:{YOUR_ACCOUNT_ID}:function:{Registration_id}-devicestatus-lambda-function'
    }

    # Function to add CORS to a resource
    def add_cors_to_resource(api_id, resource_id):
        # Add OPTIONS method
        apigateway_client.put_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod='OPTIONS',
            authorizationType='NONE'
        )

        # Add mock integration for OPTIONS method
        apigateway_client.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod='OPTIONS',
            type='MOCK',
            requestTemplates={
                'application/json': '{"statusCode": 200}'
            }
        )

        # Add response headers for CORS
        apigateway_client.put_method_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod='OPTIONS',
            statusCode='200',
            responseParameters={
                'method.response.header.Access-Control-Allow-Headers': False,
                'method.response.header.Access-Control-Allow-Methods': False,
                'method.response.header.Access-Control-Allow-Origin': False
            }
        )

        apigateway_client.put_integration_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod='OPTIONS',
            statusCode='200',
            responseParameters={
                'method.response.header.Access-Control-Allow-Headers': "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'",
                'method.response.header.Access-Control-Allow-Methods': "'GET,OPTIONS'",
                'method.response.header.Access-Control-Allow-Origin': "'*'"
            }
        )

    # Add GET method and Lambda integration to each resource
    for resource_name, resource_id in resource_ids.items():
        # Add GET method
        apigateway_client.put_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod='GET',
            authorizationType='NONE'
        )

        # Add Lambda integration
        apigateway_client.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod='GET',
            type='AWS_PROXY',
            integrationHttpMethod='POST',
            uri=f'arn:aws:apigateway:{boto3.Session().region_name}:lambda:path/2015-03-31/functions/{lambda_arns[resource_name]}/invocations'
        )

        # Add CORS to the resource
        add_cors_to_resource(api_id, resource_id)

    # Add query string parameter to the GET method of 'rfid' resource
    apigateway_client.update_method(
        restApiId=api_id,
        resourceId=resource_ids['rfidstatus'],
        httpMethod='GET',
        patchOperations=[
            {
                'op': 'add',
                'path': '/requestParameters/method.request.querystring.Rfid',
                'value': 'true'
            },
            {
                'op': 'add',
                'path': '/requestParameters/method.request.querystring.timestamp',
                'value': 'true'
            }
        ]
    )
    deploy_response = apigateway_client.create_deployment(
        restApiId=api_id,
        stageName='prod',  # You can change this to your desired stage name
        description='Deployment for updated GET methods with query parameters for multiple resources'
    )
    response = lambda_client.add_permission(
        FunctionName=f'{Registration_id}-livetracking-lambda-function',
        StatementId='apigateway-invoke-permission',
        Action='lambda:InvokeFunction',
        Principal='apigateway.amazonaws.com',
        SourceArn=f'arn:aws:execute-api:us-east-1:079921713039:{api_id}/*/GET/{resource_names[0]}'
    )
    response = lambda_client.add_permission(
        FunctionName=f'{Registration_id}-rfidstatus-lambda-function',
        StatementId='apigateway-invoke-permission',
        Action='lambda:InvokeFunction',
        Principal='apigateway.amazonaws.com',
        SourceArn=f'arn:aws:execute-api:us-east-1:079921713039:{api_id}/*/GET/{resource_names[1]}'
    )
    response = lambda_client.add_permission(
        FunctionName=f'{Registration_id}-devicestatus-lambda-function',
        StatementId='apigateway-invoke-permission',
        Action='lambda:InvokeFunction',
        Principal='apigateway.amazonaws.com',
        SourceArn=f'arn:aws:execute-api:us-east-1:079921713039:{api_id}/*/GET/{resource_names[2]}'
    )
    api_url1 = f"https://{api_id}.execute-api.us-east-1.amazonaws.com/prod/{resource_names[0]}"
    api_url2 = f"https://{api_id}.execute-api.us-east-1.amazonaws.com/prod/{resource_names[1]}?Rfid=&timestamp="
    api_url3 = f"https://{api_id}.execute-api.us-east-1.amazonaws.com/prod/{resource_names[2]}"

    print(api_url1)
    print(api_url2)
    print(api_url3)
    print(f"Created API with ID: {api_id}")
    print(f"Resources: {resource_ids}")


def main(Registration_id):
    Registration_id = Registration_id.lower()
    if "_" in Registration_id:
        Registration_id = Registration_id.replace('_',"-")
    thing_name = Registration_id + "Thing"
    policy_name = thing_name + "_POLICY"
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    #
    # Create Thing
    thing_arn = create_thing(thing_name)
    if not thing_arn:
        return

    # Create Policy
    policy_arn = create_policy(policy_name, policy_document)
    if not policy_arn:
        return

    certificate_arn, certificate_pem, key_pair = create_certificate_and_store_in_s3(Registration_id)

    # # Attach Policy to Certificate
    attach_policy_to_certificate(policy_name, certificate_arn)

    # Attach Thing to Certificate
    attach_thing_to_certificate(thing_name, certificate_arn)

    # Liver Tracking Api
    live_tracking(Registration_id)

    # Device status Api
    device_status(Registration_id)

    # Rfid status Api
    rfid_status(Registration_id)

    print("Setup complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process some integers.")
    parser.add_argument('Registration_id', type=str, help='Registration ID variable')
    args = parser.parse_args()
    main(args.Registration_id)
