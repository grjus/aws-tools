from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from botocore.exceptions import ClientError
from pydantic import ValidationError

from aws_tools.aws import AwsContext, create_context
from aws_tools.cloudformation import StackOwnership
from aws_tools.cleanup import CleanupError, apply_findings
from aws_tools.config import AppConfig, ExclusionRule, load_config
from aws_tools.filtering import apply_report_filters, parse_filters
from aws_tools.models import CleanupAction, Finding, Report, stable_finding_id
from aws_tools.reports import load_report
from aws_tools.scanners import cost_risk, orphaned


class CoreContractTest(unittest.TestCase):
    def test_report_round_trip(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "report.json"
            finding = _logs_finding()
            Report(tool="logs-retention", findings=[finding]).write_json(path)

            loaded = load_report(path)

        self.assertEqual(loaded.findings[0].id, "logs-retention-test")
        self.assertEqual(
            loaded.findings[0].cleanup_action.name, "logs.put_retention_policy"
        )

    def test_cleanup_dry_run_does_not_require_aws_context(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "report.json"
            Report(tool="logs-retention", findings=[_logs_finding()]).write_json(path)

            messages = apply_findings(
                context=None,
                report_path=path,
                finding_ids=["logs-retention-test"],
                execute=False,
            )

        self.assertEqual(
            messages,
            [
                "DRY-RUN logs-retention-test: set retention on "
                "/aws/lambda/test to 30 days"
            ],
        )

    def test_cleanup_all_selects_cleanup_eligible_findings(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "report.json"
            Report(
                tool="logs-retention",
                findings=[_logs_finding(), _non_cleanup_finding()],
            ).write_json(path)

            messages = apply_findings(
                context=None,
                report_path=path,
                finding_ids=["ALL"],
                execute=False,
            )

        self.assertEqual(len(messages), 1)
        self.assertIn("logs-retention-test", messages[0])

    def test_cleanup_all_rejects_mixed_ids(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "report.json"
            Report(tool="logs-retention", findings=[_logs_finding()]).write_json(path)

            with self.assertRaises(CleanupError):
                apply_findings(
                    context=None,
                    report_path=path,
                    finding_ids=["ALL", "logs-retention-test"],
                    execute=False,
                )

    def test_cleanup_all_requires_eligible_findings(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "report.json"
            Report(
                tool="orphaned",
                findings=[_non_cleanup_finding()],
            ).write_json(path)

            with self.assertRaises(CleanupError):
                apply_findings(
                    context=None,
                    report_path=path,
                    finding_ids=["ALL"],
                    execute=False,
                )

    def test_cleanup_all_explains_old_orphaned_reports(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "report.json"
            Report(
                tool="orphaned",
                findings=[
                    Finding(
                        id="old-log-group",
                        tool="orphaned",
                        account_id="123456789012",
                        region="eu-west-1",
                        service="logs",
                        resource_type="log-group",
                        resource_id="/aws/lambda/old",
                        recommendation="Review ownership before cleanup",
                    )
                ],
            ).write_json(path)

            with self.assertRaisesRegex(
                CleanupError,
                "Regenerate the report",
            ):
                apply_findings(
                    context=None,
                    report_path=path,
                    finding_ids=["ALL"],
                    execute=False,
                )

    def test_delete_log_group_cleanup_executes_delete(self):
        finding = _orphaned_log_group_finding()
        context = AwsContext(
            session=None,
            account_id="123456789012",
            profile="dev",
            regions=["eu-west-1"],
        )
        logs = FakeLogsClient()

        with patch("aws_tools.cleanup.client", return_value=logs):
            message = apply_findings_from_report(
                context,
                [finding],
                ["orphaned-log-group"],
                True,
            )[0]

        self.assertEqual(message, "APPLIED orphaned-log-group: log group deleted")
        self.assertEqual(logs.deleted, ["/aws/lambda/orphaned"])

    def test_delete_empty_bucket_cleanup_executes_delete(self):
        finding = _orphaned_bucket_finding()
        context = AwsContext(
            session=None,
            account_id="123456789012",
            profile="dev",
            regions=["eu-west-1"],
        )
        s3 = FakeDeleteBucketClient()

        with patch("aws_tools.cleanup.client", return_value=s3):
            message = apply_findings_from_report(
                context,
                [finding],
                ["orphaned-bucket"],
                True,
            )[0]

        self.assertEqual(message, "APPLIED orphaned-bucket: bucket deleted")
        self.assertEqual(s3.deleted, ["orphaned-bucket"])

    def test_delete_bucket_refuses_non_empty_bucket(self):
        finding = _orphaned_bucket_finding()
        context = AwsContext(
            session=None,
            account_id="123456789012",
            profile="dev",
            regions=["eu-west-1"],
        )
        s3 = FakeDeleteBucketClient(key_count=1)

        with patch("aws_tools.cleanup.client", return_value=s3):
            with self.assertRaises(CleanupError):
                apply_findings_from_report(
                    context,
                    [finding],
                    ["orphaned-bucket"],
                    True,
                )

        self.assertEqual(s3.deleted, [])

    def test_log_retention_days_are_validated(self):
        with self.assertRaises(ValidationError):
            AppConfig(log_retention_days=2)

    def test_exclusion_rule_requires_a_matcher(self):
        with self.assertRaises(ValidationError):
            ExclusionRule(reason="too broad")

    def test_stable_finding_id_is_deterministic(self):
        first = stable_finding_id(
            "tool", "123", "eu-west-1", "ec2", "volume", "vol-123"
        )
        second = stable_finding_id(
            "tool", "123", "eu-west-1", "ec2", "volume", "vol-123"
        )

        self.assertEqual(first, second)

    def test_parse_filter_supports_service(self):
        filters = parse_filters(["logs"])

        self.assertEqual(filters[0].service, "logs")
        self.assertIsNone(filters[0].resource_type)

    def test_parse_filter_supports_service_and_resource_type(self):
        filters = parse_filters(["cloudfront:distribution"])

        self.assertEqual(filters[0].service, "cloudfront")
        self.assertEqual(filters[0].resource_type, "distribution")

    def test_report_filter_keeps_matching_findings(self):
        report = Report(
            tool="orphaned",
            findings=[
                _non_cleanup_finding(),
                _cloudfront_finding(),
            ],
        )

        filtered = apply_report_filters(
            report,
            ["cloudfront:distribution"],
        )

        self.assertEqual(len(filtered.findings), 1)
        self.assertEqual(filtered.findings[0].service, "cloudfront")
        self.assertEqual(filtered.filters, ["cloudfront:distribution"])

    def test_report_filter_supports_comma_separated_services(self):
        report = Report(
            tool="orphaned",
            findings=[
                _non_cleanup_finding(),
                _cloudfront_finding(),
            ],
        )

        filtered = apply_report_filters(report, ["ec2,cloudfront"])

        self.assertEqual(len(filtered.findings), 2)

    def test_cost_risk_uses_direct_describe_addresses(self):
        context = AwsContext(
            session=None,
            account_id="123456789012",
            profile="dev",
            regions=["eu-west-1"],
        )
        ec2 = FakeEc2Client()

        with patch("aws_tools.scanners.cost_risk.client", return_value=ec2):
            findings = cost_risk._ec2_cost_findings(context, "eu-west-1")

        self.assertIn("describe_addresses", ec2.calls)
        self.assertEqual(findings[0].resource_id, "eipalloc-123")

    def test_read_only_role_loaded_from_env(self):
        with patch.dict(
            "os.environ",
            {"AWS_READ_ONLY_ROLE_ARN": "arn:aws:iam::123:role/ReadOnly"},
            clear=True,
        ):
            config = load_config(config_path=Path("/tmp/missing-config.yaml"))

        self.assertEqual(
            config.read_only_role_arn,
            "arn:aws:iam::123:role/ReadOnly",
        )

    def test_create_context_assumes_read_only_role(self):
        config = AppConfig(
            regions=["eu-west-1"],
            read_only_role_arn="arn:aws:iam::123:role/ReadOnly",
        )

        with patch("aws_tools.aws.boto3.Session", FakeBoto3Session):
            context = create_context(config)

        self.assertEqual(context.account_id, "999999999999")
        self.assertEqual(
            context.assumed_role_arn,
            "arn:aws:iam::123:role/ReadOnly",
        )

    def test_s3_stack_owned_bucket_is_not_orphaned(self):
        context = AwsContext(
            session=None,
            account_id="123456789012",
            profile="dev",
            regions=["eu-west-1"],
        )

        with patch(
            "aws_tools.scanners.orphaned.client",
            return_value=FakeS3Client(),
        ):
            findings = orphaned._s3_findings(
                context,
                AppConfig(),
                {
                    "stack-owned-bucket": _stack_owner(
                        "stack-owned-bucket",
                    )
                },
                False,
            )

        self.assertEqual(findings, [])

    def test_cloudfront_distribution_is_reported_when_unowned(self):
        context = AwsContext(
            session=None,
            account_id="123456789012",
            profile="dev",
            regions=["eu-west-1"],
        )

        with patch(
            "aws_tools.scanners.orphaned.client",
            return_value=FakeCloudFrontClient(),
        ):
            findings = orphaned._cloudfront_findings(
                context,
                AppConfig(),
                {},
                False,
                [],
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].service, "cloudfront")
        self.assertEqual(findings[0].resource_id, "E123456789")

    def test_include_managed_shows_stack_owned_cloudfront_distribution(self):
        context = AwsContext(
            session=None,
            account_id="123456789012",
            profile="dev",
            regions=["eu-west-1"],
        )

        with patch(
            "aws_tools.scanners.orphaned.client",
            return_value=FakeCloudFrontClient(),
        ):
            findings = orphaned._cloudfront_findings(
                context,
                AppConfig(),
                {"E123456789": _stack_owner("E123456789")},
                True,
                [],
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].evidence[:3],
            [
                "CloudFormation physical resource ID found",
                "Stack: test-stack (arn:aws:cloudformation:stack/test-stack)",
                "Logical resource: Resource",
            ],
        )

    def test_dynamodb_table_is_reported_when_unowned(self):
        with patch(
            "aws_tools.scanners.orphaned.client",
            return_value=FakeDynamoDbClient(),
        ):
            resources = orphaned._dynamodb_resources(_context(), "eu-west-1")

        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0].service, "dynamodb")
        self.assertEqual(resources[0].resource_type, "table")
        self.assertEqual(resources[0].resource_id, "table-one")

    def test_opensearch_serverless_collection_is_reported(self):
        with patch(
            "aws_tools.scanners.orphaned.client",
            return_value=FakeOpenSearchServerlessClient(),
        ):
            resources = orphaned._opensearch_serverless_resources(
                _context(),
                "eu-west-1",
            )

        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0].service, "opensearchserverless")
        self.assertEqual(resources[0].resource_type, "collection")
        self.assertEqual(resources[0].resource_id, "collection-id")

    def test_bedrock_knowledge_base_is_reported(self):
        with patch(
            "aws_tools.scanners.orphaned.client",
            return_value=FakeBedrockAgentClient(),
        ):
            resources = orphaned._bedrock_resources(_context(), "eu-west-1")

        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0].service, "bedrock-agent")
        self.assertEqual(resources[0].resource_type, "knowledge-base")
        self.assertEqual(resources[0].resource_id, "KB123")

    def test_sagemaker_endpoint_is_reported(self):
        with patch(
            "aws_tools.scanners.orphaned.client",
            return_value=FakeSageMakerClient(),
        ):
            resources = orphaned._sagemaker_named_resources(
                FakeSageMakerClient(),
                "endpoint",
            )

        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0].service, "sagemaker")
        self.assertEqual(resources[0].resource_type, "endpoint")
        self.assertEqual(resources[0].resource_id, "endpoint-one")

    def test_orphaned_log_group_has_delete_action(self):
        finding = orphaned._finding(
            _context(),
            AppConfig(),
            "eu-west-1",
            orphaned.ResourceIdentity(
                service="logs",
                resource_type="log-group",
                resource_id="/aws/lambda/orphaned",
            ),
            {},
        )

        self.assertTrue(finding.cleanup_eligible)
        self.assertEqual(finding.cleanup_action.name, "logs.delete_log_group")

    def test_orphaned_bucket_has_guarded_delete_action(self):
        finding = orphaned._finding(
            _context(),
            AppConfig(),
            "global",
            orphaned.ResourceIdentity(
                service="s3",
                resource_type="bucket",
                resource_id="orphaned-bucket",
            ),
            {},
        )

        self.assertTrue(finding.cleanup_eligible)
        self.assertEqual(
            finding.cleanup_action.name,
            "s3.delete_bucket_if_empty",
        )


def _logs_finding() -> Finding:
    return Finding(
        id="logs-retention-test",
        tool="logs-retention",
        account_id="123456789012",
        region="eu-west-1",
        service="logs",
        resource_type="log-group",
        resource_id="/aws/lambda/test",
        cleanup_eligible=True,
        cleanup_action=CleanupAction(
            name="logs.put_retention_policy",
            parameters={
                "log_group_name": "/aws/lambda/test",
                "retention_days": 30,
            },
        ),
        recommendation="Set retention",
    )


def _orphaned_log_group_finding() -> Finding:
    return Finding(
        id="orphaned-log-group",
        tool="orphaned",
        account_id="123456789012",
        region="eu-west-1",
        service="logs",
        resource_type="log-group",
        resource_id="/aws/lambda/orphaned",
        cleanup_eligible=True,
        cleanup_action=CleanupAction(
            name="logs.delete_log_group",
            parameters={"log_group_name": "/aws/lambda/orphaned"},
        ),
        recommendation="Delete orphaned log group",
    )


def _orphaned_bucket_finding() -> Finding:
    return Finding(
        id="orphaned-bucket",
        tool="orphaned",
        account_id="123456789012",
        region="global",
        service="s3",
        resource_type="bucket",
        resource_id="orphaned-bucket",
        cleanup_eligible=True,
        cleanup_action=CleanupAction(
            name="s3.delete_bucket_if_empty",
            parameters={"bucket_name": "orphaned-bucket"},
        ),
        recommendation="Delete empty orphaned bucket",
    )


def _non_cleanup_finding() -> Finding:
    return Finding(
        id="orphaned-test",
        tool="orphaned",
        account_id="123456789012",
        region="eu-west-1",
        service="ec2",
        resource_type="volume",
        resource_id="vol-123",
        recommendation="Review ownership before cleanup",
    )


def _cloudfront_finding() -> Finding:
    return Finding(
        id="orphaned-cloudfront",
        tool="orphaned",
        account_id="123456789012",
        region="global",
        service="cloudfront",
        resource_type="distribution",
        resource_id="E123456789",
        recommendation="Review ownership before cleanup",
    )


def _stack_owner(resource_id: str) -> StackOwnership:
    del resource_id
    return StackOwnership(
        stack_id="arn:aws:cloudformation:stack/test-stack",
        stack_name="test-stack",
        logical_resource_id="Resource",
        resource_type="AWS::CloudFront::Distribution",
        region="eu-west-1",
    )


def _context() -> AwsContext:
    return AwsContext(
        session=None,
        account_id="123456789012",
        profile="dev",
        regions=["eu-west-1"],
    )


def apply_findings_from_report(
    context: AwsContext | None,
    findings: list[Finding],
    finding_ids: list[str],
    execute: bool,
) -> list[str]:
    with TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "report.json"
        Report(tool="test", findings=findings).write_json(path)
        return apply_findings(context, path, finding_ids, execute)


class FakeEc2Client:
    def __init__(self):
        self.calls = []

    def get_paginator(self, operation_name):
        return FakePaginator(operation_name)

    def describe_addresses(self):
        self.calls.append("describe_addresses")
        return {"Addresses": [{"AllocationId": "eipalloc-123"}]}


class FakePaginator:
    def __init__(self, operation_name):
        self.operation_name = operation_name

    def paginate(self, **kwargs):
        del kwargs
        if self.operation_name == "describe_volumes":
            return [{"Volumes": []}]
        if self.operation_name == "describe_instances":
            return [{"Reservations": []}]
        raise AssertionError(f"Unexpected paginator: {self.operation_name}")


class FakeBoto3Session:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.region_name = kwargs.get("region_name")

    def client(self, service):
        if service != "sts":
            raise AssertionError(f"Unexpected client: {service}")
        return FakeStsClient(assumed="aws_access_key_id" in self.kwargs)


class FakeStsClient:
    def __init__(self, assumed):
        self.assumed = assumed

    def assume_role(self, RoleArn, RoleSessionName):
        self.role_arn = RoleArn
        self.session_name = RoleSessionName
        return {
            "Credentials": {
                "AccessKeyId": "access",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            }
        }

    def get_caller_identity(self):
        account = "999999999999" if self.assumed else "123456789012"
        return {"Account": account}


class FakeS3Client:
    def list_buckets(self):
        return {"Buckets": [{"Name": "stack-owned-bucket"}]}

    def get_bucket_tagging(self, Bucket):
        del Bucket
        return {"TagSet": []}


class FakeCloudFrontClient:
    def get_paginator(self, operation_name):
        if operation_name != "list_distributions":
            raise AssertionError(f"Unexpected paginator: {operation_name}")
        return FakeCloudFrontPaginator()

    def list_tags_for_resource(self, Resource):
        del Resource
        return {"Tags": {"Items": []}}


class FakeCloudFrontPaginator:
    def paginate(self):
        return [
            {
                "DistributionList": {
                    "Items": [
                        {
                            "Id": "E123456789",
                            "ARN": (
                                "arn:aws:cloudfront::123456789012:"
                                "distribution/E123456789"
                            ),
                            "DomainName": "example.cloudfront.net",
                        }
                    ]
                }
            }
        ]


class FakeDynamoDbClient:
    def get_paginator(self, operation_name):
        if operation_name != "list_tables":
            raise AssertionError(f"Unexpected paginator: {operation_name}")
        return FakeDynamoDbPaginator()

    def describe_table(self, TableName):
        return {
            "Table": {
                "TableName": TableName,
                "TableArn": f"arn:aws:dynamodb:eu-west-1:123:table/{TableName}",
            }
        }


class FakeDynamoDbPaginator:
    def paginate(self):
        return [{"TableNames": ["table-one"]}]


class FakeOpenSearchServerlessClient:
    def list_collections(self):
        return {
            "collectionSummaries": [
                {
                    "id": "collection-id",
                    "arn": "arn:aws:aoss:eu-west-1:123:collection/collection-id",
                    "name": "vectors",
                }
            ]
        }


class FakeBedrockAgentClient:
    def get_paginator(self, operation_name):
        if operation_name != "list_knowledge_bases":
            raise AssertionError(f"Unexpected paginator: {operation_name}")
        return FakeBedrockKnowledgeBasePaginator()


class FakeBedrockKnowledgeBasePaginator:
    def paginate(self):
        return [{"knowledgeBaseSummaries": [{"knowledgeBaseId": "KB123"}]}]


class FakeSageMakerClient:
    def get_paginator(self, operation_name):
        if operation_name != "list_endpoints":
            raise AssertionError(f"Unexpected paginator: {operation_name}")
        return FakeSageMakerEndpointPaginator()


class FakeSageMakerEndpointPaginator:
    def paginate(self):
        return [
            {
                "Endpoints": [
                    {
                        "EndpointName": "endpoint-one",
                        "EndpointArn": "arn:aws:sagemaker:eu-west-1:123:endpoint/one",
                    }
                ]
            }
        ]


class FakeLogsClient:
    def __init__(self):
        self.deleted = []

    def describe_log_groups(self, logGroupNamePrefix, limit):
        del limit
        return {"logGroups": [{"logGroupName": logGroupNamePrefix}]}

    def delete_log_group(self, logGroupName):
        self.deleted.append(logGroupName)


class FakeDeleteBucketClient:
    def __init__(self, key_count: int = 0):
        self.key_count = key_count
        self.deleted = []

    def head_bucket(self, Bucket):
        del Bucket

    def get_bucket_versioning(self, Bucket):
        del Bucket
        return {}

    def get_object_lock_configuration(self, Bucket):
        del Bucket
        raise _client_error("ObjectLockConfigurationNotFoundError")

    def get_bucket_replication(self, Bucket):
        del Bucket
        raise _client_error("ReplicationConfigurationNotFoundError")

    def list_objects_v2(self, Bucket, MaxKeys):
        del Bucket, MaxKeys
        return {"KeyCount": self.key_count}

    def list_object_versions(self, Bucket, MaxKeys):
        del Bucket, MaxKeys
        return {}

    def delete_bucket(self, Bucket):
        self.deleted.append(Bucket)


def _client_error(code: str) -> ClientError:
    return ClientError(
        {
            "Error": {
                "Code": code,
                "Message": code,
            }
        },
        "TestOperation",
    )


if __name__ == "__main__":
    unittest.main()
