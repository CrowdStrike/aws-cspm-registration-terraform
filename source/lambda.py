"""
CrowdStrike Falcon Horizon Registration Lambda Function

______                         __ _______ __         __ __
|      |.----.-----.--.--.--.--|  |     __|  |_.----.|__|  |--.-----.
|   ---||   _|  _  |  |  |  |  _  |__     |   _|   _||  |    <|  -__|
|______||__| |_____|________|_____|_______|____|__|  |__|__|__|_____|

Falcon Horizon Registration Lambda Function v1.0

Creation date: 06.01.23 - ryanjpayne@CrowdStrike
"""

import json
import logging
import os
import boto3
import base64
from botocore.exceptions import ClientError
import falconpy

class CrowdStrikeApiError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(f"Received non-success response {code} while calling API. Error: {message}")

def get_secret(secret_name, secret_region):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=secret_region
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            raise e
    else:
        # Decrypts secret using the associated KMS key.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])
        return secret

def get_env(key):
    """Get the value of an environment variable.
    Args:
        key (str): The name of the environment variable.
    Returns:
        str: The value of the environment variable.
    Raises:
        KeyError: If the environment variable is not set.
    """
    value = os.environ.get(key)
    if value is None:
        raise KeyError(f"Required environment variable: {key} is not set.")
    return value

def get_management_id():
    """ Get the management Id from AWS Organization - Only on management"""
    ORG = boto3.client('organizations')
    managementID = ''
    try:
        orgIDstr = ORG.list_roots()['Roots'][0]['Arn'].rsplit('/')[1]
        managementID = ORG.list_roots()['Roots'][0]['Arn'].rsplit(':')[4]
        return orgIDstr, managementID
    except Exception as e:
        logger.error('This stack runs only on the management of the AWS Organization')
        return False

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# CONSTANTS
SUCCESS = "SUCCESS"
FAILED = "FAILED"

VERSION = "1.0.0"
NAME = "crowdstrike-cloud-horizon-tf"
USER_AGENT = ("%s/%s" % (NAME, VERSION))

SECRET_NAME = get_env("SECRET_NAME")
SECRET_REGION = get_env("SECRET_REGION")
CS_CLOUD = get_env("CS_CLOUD")
CT_REGION = get_env("CT_REGION")
IOA = get_env("IOA")

secret_str = get_secret(SECRET_NAME, SECRET_REGION)
secrets_dict = json.loads(secret_str)
FalconClientId = secrets_dict['FalconClientId']
FalconSecret = secrets_dict['FalconSecret']

def lambda_handler(event, context):
    logger.info(event)
    OrgId, AccountId = get_management_id()
    try:
        horizon = falconpy.CSPMRegistration(client_id=FalconClientId,
                                client_secret=FalconSecret,
                                base_url=CS_CLOUD,
                                user_agent=USER_AGENT
                                )
        if event['tf']['action'] in ['create']:
            response = horizon.create_aws_account(account_id=AccountId,
                                                account_type="commercial",
                                                behavior_assessment_enabled=IOA,
                                                cloudtrail_region=CT_REGION,
                                                is_master="true",
                                                organization_id=OrgId,
                                                sensor_management_enabled="true",
                                                use_existing_cloudtrail="true",
                                                user_agent=USER_AGENT
                                                #
                                                )
            status = response['status_code']
            if response['status_code'] == 400:
                error = response['body']['errors'][0]['message']
                logger.info('Account Registration Failed with reason....{}'.format(error))
                return (error)
            elif response['status_code'] == 201:
                logger.info(f'Account registration succeeded! {status}')
                return (response)

        elif event['tf']['action'] in ['update']:
            response = horizon.create_aws_account(account_id=AccountId,
                                                organization_id=OrgId,
                                                cloudtrail_region=CT_REGION,
                                                user_agent=USER_AGENT,
                                                parameters={"account_type": "commercial"}
                                                )
            status = response['status_code']
            if response['status_code'] == 400:
                error = response['body']['errors'][0]['message']
                logger.info('Account Registration Failed with reason....{}'.format(error))
                return (error)
            elif response['status_code'] == 201:
                logger.info(f'Account registration succeeded! {status}')
                return (response)

        elif event['tf']['action'] in ['delete']:
            logger.info('Event = ' + event['tf']['action'])
            response = horizon.delete_aws_account(organization_ids=OrgId,
                                                user_agent=USER_AGENT
                                                )
            return (response)
    except Exception as err:  
        logger.info('Registration Failed {}'.format(err))