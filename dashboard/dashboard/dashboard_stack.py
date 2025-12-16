from aws_cdk import (
    aws_s3 as s3,
    aws_iam as iam,
    Stack,
    RemovalPolicy,
    aws_dynamodb as dynamodb,
    aws_opensearchservice as opensearch,
    aws_ec2 as ec2,
    aws_cognito as cognito,
    aws_logs as logs,
    aws_osis as osis,
    CfnTag
)
from constructs import Construct
import os

# Get current directory
current_dir = os.getcwd()
file = f"{current_dir}/dashboard/template.txt"

# Function to generate the OpenSearch Ingestion pipeline YAML configuration
def generate_template(file, replace_value):
    try:
        with open(file, 'r') as f:
            content = f.read()
            for key, val in replace_value.items():
                content = content.replace(key, val)
            return content
    except FileNotFoundError:
        print(f"The file {file} does not exist.")
        return None
    except IOError:
        print(f"Error reading the file {file}.")
        return None

class OpenSearchDynamoDBStreamingStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        REGION_NAME = self.region

        # Create Cognito User Pool
        cognito_pool = cognito.UserPool(self, "CognitoUserPoolStreaming",
                                    sign_in_aliases=cognito.SignInAliases(email=True),
                                    auto_verify=cognito.AutoVerifiedAttrs(email=True),
                                    standard_attributes=cognito.StandardAttributes(
                                        email=cognito.StandardAttribute(mutable=True, required=True)
                                    ), 
                                    removal_policy=RemovalPolicy.DESTROY
                                    )
        
        # Create User Pool Client
        cognito_pool_client = cognito_pool.add_client(
            "CognitoUserPoolClientStreaming",
            user_pool_client_name="CognitoUserPoolClientStreaming",
            generate_secret=False,
        )

        # Add domain
        domain = cognito_pool.add_domain("DomainStreaming", 
                    cognito_domain=cognito.CognitoDomainOptions(
                        domain_prefix="opensearch-ddb-stream"
                    )
                )

        # Identity Pool
        cognito_identity_pool = cognito.CfnIdentityPool(self, "CognitoIdentityPoolStreaming",
                                                    allow_unauthenticated_identities=False,
                                                    cognito_identity_providers=[
                                                        cognito.CfnIdentityPool.CognitoIdentityProviderProperty(
                                                            client_id=cognito_pool_client.user_pool_client_id,
                                                            provider_name=cognito_pool.user_pool_provider_name
                                                        )
                                                    ])
        cognito_identity_pool.apply_removal_policy(RemovalPolicy.DESTROY)
        identity_pool_id = cognito_identity_pool.ref

        # Auth Role
        auth_role = iam.Role(self, "AuthRoleStreaming", 
            assumed_by = iam.FederatedPrincipal(
                federated = 'cognito-identity.amazonaws.com',
                conditions = {
                    "StringEquals": { "cognito-identity.amazonaws.com:aud": identity_pool_id },
                    "ForAnyValue:StringLike": { "cognito-identity.amazonaws.com:amr": "authenticated" }
                },
                assume_role_action= "sts:AssumeRoleWithWebIdentity"
            )
        )
        
        cognito.CfnIdentityPoolRoleAttachment(
            self, "IdentityPoolRoleAttachmentStreaming",
            identity_pool_id=cognito_identity_pool.ref,
            roles={"authenticated": auth_role.role_arn}
        )

        auth_policy = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["cognito-identity:GetCredentialsForIdentity"],
            resources=["*"]
        )
        auth_role.add_to_policy(auth_policy)

        cognito_user_pool_id = cognito_pool.user_pool_id
        auth_role_arn = auth_role.role_arn

        # IAM Role for OpenSearch access
        access_role = iam.Role(self, "OpenSearchAccessRoleStreaming",
                       assumed_by=iam.ServicePrincipal("opensearchservice.amazonaws.com"),
                       managed_policies=[
                           iam.ManagedPolicy.from_aws_managed_policy_name("AmazonOpenSearchServiceCognitoAccess"),
                           iam.ManagedPolicy.from_aws_managed_policy_name("AmazonOpenSearchIngestionFullAccess"),
                           iam.ManagedPolicy.from_aws_managed_policy_name("AmazonOpenSearchServiceFullAccess"),
                       ]
                    )
        access_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["es:*"],
            resources=["*"]
        ))

        # IAM Role for OpenSearch Ingestion
        sts_role = iam.Role(self, "OpenSearchIngestionRoleStreaming",
                   assumed_by=iam.CompositePrincipal(
                       iam.ServicePrincipal("osis-pipelines.amazonaws.com"),
                       iam.ServicePrincipal("opensearchservice.amazonaws.com")
                   ),
                   managed_policies=[
                       iam.ManagedPolicy.from_aws_managed_policy_name("AmazonDynamoDBFullAccess"),
                       iam.ManagedPolicy.from_aws_managed_policy_name("AmazonOpenSearchServiceFullAccess"),
                       iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3FullAccess"),
                       iam.ManagedPolicy.from_aws_managed_policy_name("AmazonOpenSearchIngestionFullAccess")
                   ]
        )

        # OpenSearch Domain
        opensearch_domain = opensearch.Domain(self, "OpenSearchDDBStreamingDomain",
                                   version=opensearch.EngineVersion.OPENSEARCH_1_3,
                                   capacity=opensearch.CapacityConfig(
                                       data_nodes=1,
                                       data_node_instance_type="r5.large.search",
                                       multi_az_with_standby_enabled=False
                                   ),
                                   ebs=opensearch.EbsOptions(
                                       volume_size=10, 
                                       volume_type=ec2.EbsDeviceVolumeType.GP3
                                   ),
                                   cognito_dashboards_auth=opensearch.CognitoOptions(
                                           user_pool_id=cognito_user_pool_id,
                                           identity_pool_id=identity_pool_id,
                                           role=access_role
                                       ),  
                                   removal_policy=RemovalPolicy.DESTROY
                                   )
        opensearch_domain.add_access_policies(
            iam.PolicyStatement(
                actions=["es:*"],
                effect=iam.Effect.ALLOW,
                principals=[iam.AccountPrincipal(self.account), iam.ArnPrincipal(auth_role_arn)],
                resources=[f"{opensearch_domain.domain_arn}/*"]
            )
        )

        # S3 Backup Bucket
        s3_backup_bucket = s3.Bucket(
            self,
            "OpenSearchDDBStreamingBackupBucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            bucket_name=f"opensearch-dynamodb-streaming-backup-{self.account}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            versioned=True,
            removal_policy=RemovalPolicy.DESTROY
        )

        # DynamoDB Table
        dynamodb_table = dynamodb.Table(
            self,
            "DynamoDBTableStreaming",
            partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="timestamp", type=dynamodb.AttributeType.NUMBER),
            table_name="opensearch-dynamodb-streaming-table",
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            stream=dynamodb.StreamViewType.NEW_IMAGE,
            removal_policy=RemovalPolicy.DESTROY
        )

        # CloudWatch Log Group
        cloudwatch_logs_group = logs.LogGroup(
            self,
            "OpenSearchIngestionStreamingLogGroup",
            log_group_name="/aws/vendedlogs/OpenSearchIntegrationStreaming/opensearch-dynamodb-ingestion-pipeline",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY
        )

        # Generate pipeline configuration
        replace_value = {
            "REGION_NAME": str(REGION_NAME),
            "BUCKET_NAME": str(s3_backup_bucket.bucket_name),
            "DYNAMODB_TABLE_ARN": str(dynamodb_table.table_arn),
            "STS_ROLE_ARN": str(sts_role.role_arn),
            "OpenSearch_DOMAIN": str(opensearch_domain.domain_endpoint),
        }
        pipeline_configuration_body = generate_template(file, replace_value)
        print(pipeline_configuration_body)

        # Create OSIS Pipeline
        cfn_pipeline = osis.CfnPipeline(self, "OpenSearchDDBStreamingPipeline",
                                        pipeline_name="opensearch-dynamodb-streaming-pipeline",
                                        max_units=1,
                                        min_units=1,
                                        pipeline_configuration_body=pipeline_configuration_body,
                                        log_publishing_options={
                                            "cloudwatchLogGroupArn": cloudwatch_logs_group.log_group_arn,
                                            "enabled": True
                                        },
                                        tags=[
                                            CfnTag(key="Name", value="OpenSearchDynamoDBStreamingPipeline"),
                                            CfnTag(key="Description", value="OpenSearch Ingestion Streaming Pipeline")
                                        ]
        )
        cfn_pipeline.apply_removal_policy(RemovalPolicy.DESTROY)
