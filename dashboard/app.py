#!/usr/bin/env python3
import os
import aws_cdk as cdk

from dashboard.dashboard_stack import DashboardStack  # Keep the class name you used in dashboard_stack.py

app = cdk.App()

# Instantiate the stack with a meaningful name
DashboardStack(
    app, 
    "OpenSearchDynamoDBStreamingStack",  # Logical stack name for CloudFormation
    # Optional: specify AWS account and region
    # env=cdk.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION')),
    # env=cdk.Environment(account='123456789012', region='us-east-1'),
)

app.synth()
