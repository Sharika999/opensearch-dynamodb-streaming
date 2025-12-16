# OpenSearch DynamoDB Streaming

## Overview

OpenSearch DynamoDB Streaming is a real-time data ingestion and visualization project that implements a **Zero-ETL pipeline** between Amazon DynamoDB and Amazon OpenSearch.

The solution captures data changes from DynamoDB and indexes them into OpenSearch with minimal latency, enabling real-time search, analytics, and dashboard visualization without traditional ETL overhead.

The infrastructure is fully provisioned using **AWS CDK**, following a serverless and scalable architecture.

---

## Architecture Summary

The project provisions the following AWS components:

- **Amazon DynamoDB** – Primary data store with streams enabled
- **Amazon OpenSearch Service** – Indexing, analytics, and dashboards
- **OpenSearch Ingestion (OSIS)** – Managed ingestion pipeline
- **Amazon S3** – Backup and export storage
- **Amazon Cognito** – Authentication for OpenSearch Dashboards
- **AWS IAM** – Secure role-based access control

Data flows from DynamoDB into OpenSearch through OpenSearch Ingestion, using a declarative YAML-based pipeline configuration.

---

## How the Pipeline Works

1. Data is written or updated in a DynamoDB table.
2. DynamoDB Streams and/or export send data to Amazon S3.
3. OpenSearch Ingestion processes the data using a YAML pipeline definition.
4. Data is indexed into Amazon OpenSearch in near real time.
5. Users authenticate via Amazon Cognito to access OpenSearch Dashboards.

---

## OpenSearch Ingestion Pipeline Configuration

The core of the solution is a YAML-based ingestion pipeline that connects DynamoDB to OpenSearch.

Example configuration:

```yaml
version: "2"
dynamodb-pipeline:
  source:
    dynamodb:
      acknowledgments: true
      tables:
        - table_arn: "DYNAMODB_TABLE_ARN"
          stream:
            start_position: "LATEST"
          export:
            s3_bucket: "<<S3_BUCKET_NAME>>"
            s3_region: "<<AWS_REGION>>"
            s3_prefix: "ddb-opensearch-export/"
      aws:
        sts_role_arn: "<<STS_ROLE_ARN>>"
        region: "<<AWS_REGION>>"
  sink:
    - opensearch:
        hosts:
          - "<<OPENSEARCH_ENDPOINT>>"
        index: "dynamodb-records"
        index_type: custom
        document_id: "${getMetadata(\"primary_key\")}"
        action: "${getMetadata(\"opensearch_action\")}"
        document_version: "${getMetadata(\"document_version\")}"
        document_version_type: "external"
        aws:
          sts_role_arn: "<<STS_ROLE_ARN>>"
          region: "<<AWS_REGION>>"
