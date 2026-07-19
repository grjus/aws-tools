from __future__ import annotations

import io
import unittest
from unittest.mock import patch

from rich.console import Console

from aws_tools import logs_tail
from aws_tools.aws import AwsContext


def _context(regions=None):
    return AwsContext(
        session=None,
        account_id="123456789012",
        profile="dev",
        regions=["eu-west-1"] if regions is None else regions,
    )


class FakeDescribeLogGroupsPaginator:
    def __init__(self, names):
        self.names = names

    def paginate(self, **kwargs):
        del kwargs
        return [{"logGroups": [{"logGroupName": name} for name in self.names]}]


class FakeDescribeLogsClient:
    def __init__(self, names):
        self.names = names

    def get_paginator(self, operation_name):
        if operation_name != "describe_log_groups":
            raise AssertionError(f"Unexpected paginator: {operation_name}")
        return FakeDescribeLogGroupsPaginator(self.names)


class FakeTailLogsClient:
    def __init__(self, events_by_call):
        self.events_by_call = events_by_call
        self.calls = []

    def filter_log_events(self, **kwargs):
        self.calls.append(kwargs)
        index = len(self.calls) - 1
        events = self.events_by_call[index] if index < len(self.events_by_call) else []
        return {"events": events}


def _capturing_console():
    console = Console(file=io.StringIO(), force_terminal=False)
    captured = []
    original = console.print

    def capture(*args, **kwargs):
        captured.append(str(args[0]) if len(args) == 1 else str(args))
        return original(*args, **kwargs)

    console.print = capture  # type: ignore[method-assign]
    return console, captured


class ResolveLogGroupTest(unittest.TestCase):
    def test_single_match_returns_region_and_name(self):
        context = _context()
        fake = FakeDescribeLogsClient(["/aws/lambda/app", "/aws/lambda/other"])

        with patch("aws_tools.logs_tail.client", return_value=fake):
            region, name = logs_tail.resolve_log_group(context, "app", ["eu-west-1"])

        self.assertEqual((region, name), ("eu-west-1", "/aws/lambda/app"))

    def test_no_match_raises(self):
        context = _context()
        fake = FakeDescribeLogsClient(["/aws/lambda/app"])

        with patch("aws_tools.logs_tail.client", return_value=fake):
            with self.assertRaisesRegex(
                logs_tail.LogTailError, "No log group matching 'missing'"
            ):
                logs_tail.resolve_log_group(context, "missing", ["eu-west-1"])

    def test_multiple_matches_in_one_region_raises_with_listing(self):
        context = _context()
        fake = FakeDescribeLogsClient(["/aws/lambda/app-a", "/aws/lambda/app-b"])

        with patch("aws_tools.logs_tail.client", return_value=fake):
            with self.assertRaisesRegex(
                logs_tail.LogTailError, "Multiple log groups match 'app'"
            ) as cm:
                logs_tail.resolve_log_group(context, "app", ["eu-west-1"])

        message = str(cm.exception)
        self.assertIn("eu-west-1: /aws/lambda/app-a", message)
        self.assertIn("eu-west-1: /aws/lambda/app-b", message)

    def test_multiple_matches_across_regions_lists_all(self):
        context = _context(regions=["eu-west-1", "us-east-1"])
        clients = {
            "eu-west-1": FakeDescribeLogsClient(["/aws/lambda/app-a"]),
            "us-east-1": FakeDescribeLogsClient(["/aws/lambda/app-b"]),
        }

        def fake_client(ctx, service, region=None):
            del ctx
            self.assertEqual(service, "logs")
            return clients[region]

        with patch("aws_tools.logs_tail.client", side_effect=fake_client):
            with self.assertRaises(logs_tail.LogTailError) as cm:
                logs_tail.resolve_log_group(context, "app", context.regions)

        message = str(cm.exception)
        self.assertIn("eu-west-1: /aws/lambda/app-a", message)
        self.assertIn("us-east-1: /aws/lambda/app-b", message)

    def test_region_filter_limits_search_scope(self):
        context = _context(regions=["eu-west-1", "us-east-1"])
        fake = FakeDescribeLogsClient(["/aws/lambda/app"])

        with patch("aws_tools.logs_tail.client", return_value=fake) as mock_client:
            region, name = logs_tail.resolve_log_group(context, "app", ["eu-west-1"])

        self.assertEqual((region, name), ("eu-west-1", "/aws/lambda/app"))
        self.assertEqual(mock_client.call_count, 1)

    def test_no_regions_configured_raises(self):
        context = _context(regions=[])

        with self.assertRaisesRegex(
            logs_tail.LogTailError, "No AWS regions configured"
        ):
            logs_tail.resolve_log_group(context, "app", [])


class TailLogGroupTest(unittest.TestCase):
    def test_prints_events_and_advances_start_time(self):
        context = _context()
        first_events = [
            {
                "eventId": "e1",
                "timestamp": 1_700_000_000_000,
                "logStreamName": "stream",
                "message": "first\n",
            },
            {
                "eventId": "e2",
                "timestamp": 1_700_000_001_000,
                "logStreamName": "stream",
                "message": "second",
            },
        ]
        second_events = [
            {
                "eventId": "e3",
                "timestamp": 1_700_000_005_000,
                "logStreamName": "stream",
                "message": "third",
            },
        ]
        fake = FakeTailLogsClient([first_events, second_events])
        console, captured = _capturing_console()

        with patch("aws_tools.logs_tail.client", return_value=fake):
            logs_tail.tail_log_group(
                context,
                "/aws/lambda/app",
                "eu-west-1",
                interval=1.0,
                lookback_seconds=60,
                console=console,
                sleep=lambda _seconds: None,
                now=lambda: 1_700_000_000.0,
                max_iterations=2,
            )

        self.assertEqual(len(fake.calls), 2)
        self.assertEqual(fake.calls[0]["logGroupName"], "/aws/lambda/app")
        self.assertEqual(fake.calls[0]["startTime"], 1_700_000_000_000 - 60_000)
        # After the first poll startTime advances past the last seen event.
        self.assertEqual(fake.calls[1]["startTime"], 1_700_000_001_001)
        joined = " ".join(captured)
        self.assertIn("first", joined)
        self.assertIn("second", joined)
        self.assertIn("third", joined)

    def test_dedupes_repeated_event_ids(self):
        context = _context()
        dup_event = {
            "eventId": "dup",
            "timestamp": 1_700_000_000_000,
            "logStreamName": "stream",
            "message": "same",
        }
        fake = FakeTailLogsClient([[dup_event, dup_event], []])
        console, captured = _capturing_console()

        with patch("aws_tools.logs_tail.client", return_value=fake):
            logs_tail.tail_log_group(
                context,
                "/aws/lambda/app",
                "eu-west-1",
                interval=1.0,
                lookback_seconds=0,
                console=console,
                sleep=lambda _seconds: None,
                now=lambda: 1_700_000_000.0,
                max_iterations=2,
            )

        self.assertEqual(" ".join(captured).count("same"), 1)

    def test_rejects_non_positive_interval(self):
        context = _context()
        with self.assertRaisesRegex(logs_tail.LogTailError, "must be greater than 0"):
            logs_tail.tail_log_group(
                context,
                "/aws/lambda/app",
                "eu-west-1",
                interval=0,
                max_iterations=1,
            )


if __name__ == "__main__":
    unittest.main()
