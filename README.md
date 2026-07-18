# aws-tools

Daily AWS tools for resource management and exploration.

## Configuration

Create a local `.env` file:

```dotenv
AWS_PROFILE=dev
AWS_REGIONS=eu-west-1,us-east-1
AWS_READ_ONLY_ROLE_ARN=arn:aws:iam::123456789012:role/ReadOnlyRole
```

Optional exclusions and defaults can be stored in `.aws-tools/config.yaml`:

```yaml
log_retention_days: 30
read_only_role_arn: arn:aws:iam::123456789012:role/ReadOnlyRole
role_session_name: aws-tools-read-only
required_tags:
  - Owner
  - Environment
  - CostCenter
exclusions:
  - service: s3
    name_pattern: "my-manual-bucket-*"
    reason: "Intentionally managed outside CloudFormation"
```

## Commands

```bash
aws-tools orphaned scan
aws-tools orphaned scan --filter logs
aws-tools orphaned scan --filter cloudfront:distribution
aws-tools orphaned scan --filter s3,cloudfront
aws-tools orphaned scan --include-managed
aws-tools logs-retention scan
aws-tools cost-risk scan
aws-tools tag-compliance scan
aws-tools cleanup apply --report .aws-tools/reports/<report>.json --ids <id>
aws-tools cleanup apply --report .aws-tools/reports/<report>.json --ids ALL
aws-tools cleanup apply --report .aws-tools/reports/<report>.json --ids <id> --execute
aws-tools cleanup apply --report .aws-tools/reports/<orphaned-report>.json --ids ALL --execute
```

Scans print a console report and write JSON reports under
`.aws-tools/reports/` by default. Cleanup is dry-run unless `--execute` is
provided, and cleanup actions must reference explicit finding IDs from a
generated report. Use `--ids ALL` to select every cleanup-eligible finding from
the report. Findings without a supported cleanup action are never applied by
`ALL`.

The orphaned scanner currently emits destructive cleanup actions for orphaned
CloudWatch log groups and S3 buckets. Log group cleanup calls
`logs.delete_log_group`. S3 bucket cleanup calls `s3.delete_bucket` only after
state checks confirm the bucket exists, is not versioned, has no object lock,
has no replication configuration, and has no objects, versions, or delete
markers. The tool does not empty buckets.

Use `--filter` on scan commands to keep only services you care about in the
console output and saved JSON report. A filter can be a service such as `logs`,
or `service:resource-type` such as `cloudfront:distribution`.

When `AWS_READ_ONLY_ROLE_ARN`, `read_only_role_arn`, or
`--read-only-role-arn` is set, scan commands assume that role before reading
resources. `cleanup apply --execute` uses the base profile credentials because
it performs write actions.

Use `aws-tools orphaned scan --include-managed` when a resource is missing from
the orphan report. It includes resources classified as CloudFormation-managed
or excluded, with evidence that suppressed them from the default report. For
CloudFormation-managed resources, evidence includes the stack name, stack ID,
logical resource ID, resource type, and stack region.

## Orphaned resource coverage

`orphaned scan` currently checks EC2, EBS, Elastic IPs, NAT gateways, load
balancers, target groups, RDS instances and clusters, Lambda functions,
CloudWatch log groups, S3 buckets, CloudFront distributions, DynamoDB tables,
OpenSearch Serverless collections, Bedrock knowledge bases, and SageMaker
notebook instances, endpoints, models, jobs, domains, apps, feature groups, and
workteams.

## Roadmap

- Orphaned resources scanner.
- CloudWatch Logs retention manager.
- Cost-risk inventory.
- Security group cleanup.
- Resource tag compliance.
- S3 bucket hygiene.
- IAM access key audit.
- AMI and snapshot cleanup.
- VPC networking audit.
- CloudFormation stack health helper.
