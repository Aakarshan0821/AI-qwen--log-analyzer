from dataclasses import replace
import unittest
import sys
import types
from unittest.mock import patch

fake_elasticsearch = types.ModuleType("elasticsearch")
fake_elasticsearch.Elasticsearch = object
sys.modules.setdefault("elasticsearch", fake_elasticsearch)

from app.config import Settings
from app.errors import ValidationError
from app.services.es_service import (
    delete_logs_before,
    extract_event,
    fetch_range_events,
    parse_iso,
    search_logs,
)


def make_settings() -> Settings:
    return Settings(
        es_url="http://127.0.0.1:9200",
        es_index_pattern="pfsense-*",
        es_username=None,
        es_password=None,
        es_timeout_seconds=10,
        es_search_batch_size=500,
        detection_max_logs=10000,
        qwen_api_key=None,
        qwen_base_url="https://example.com",
        qwen_model="demo",
        ai_timeout_seconds=30,
        detection_window_minutes=10,
        suspicious_threshold=20,
        risky_ports=frozenset({22, 3389}),
        max_alerts_display=200,
        auto_refresh_seconds=60,
        enable_scheduler=False,
        auth_enabled=False,
        login_email="admin@example.com",
        login_password="test-password",
        session_secret="test-secret",
        session_max_age_seconds=86400,
    )


class EsServiceTests(unittest.TestCase):
    def test_parse_iso_invalid_raises_validation_error(self) -> None:
        with self.assertRaises(ValidationError):
            parse_iso("not-a-date")

    def test_extract_event_falls_back_to_pfsense_fields(self) -> None:
        hit = {
            "_id": "doc-1",
            "_index": "pfsense-2026.03.14",
            "_source": {
                "@timestamp": "2026-03-14T12:00:00Z",
                "message": "blocked traffic",
                "pfsense": {
                    "ip_version": "6",
                    "action": "block",
                    "column16": "10.0.0.10",
                    "column17": "10.0.0.20",
                    "column18": "12345",
                    "column19": "3389",
                },
            }
        }

        event = extract_event(hit)

        self.assertEqual(event["id"], "doc-1")
        self.assertEqual(event["index"], "pfsense-2026.03.14")
        self.assertEqual(event["event_action"], "block")
        self.assertEqual(event["source_ip"], "10.0.0.10")
        self.assertEqual(event["destination_ip"], "10.0.0.20")
        self.assertEqual(event["source_port"], 12345)
        self.assertEqual(event["destination_port"], 3389)

    def test_extract_event_uses_ipv4_pfsense_columns(self) -> None:
        hit = {
            "_id": "doc-2",
            "_index": "pfsense-2026.03.14",
            "_source": {
                "@timestamp": "2026-03-14T12:00:00Z",
                "message": "ipv4 filterlog",
                "host": {"ip": "192.168.1.1"},
                "pfsense": {
                    "ip_version": "4",
                    "column16": "17",
                    "column17": "udp",
                    "column18": "78",
                    "column19": "192.168.75.1",
                    "column20": "192.168.75.255",
                    "column21": "137",
                    "column22": "137",
                },
            },
        }

        event = extract_event(hit)

        self.assertEqual(event["source_ip"], "192.168.75.1")
        self.assertEqual(event["destination_ip"], "192.168.75.255")
        self.assertEqual(event["source_port"], 137)
        self.assertEqual(event["destination_port"], 137)

    def test_extract_event_uses_ipv6_pfsense_columns(self) -> None:
        hit = {
            "_id": "doc-3",
            "_index": "pfsense-2026.03.14",
            "_source": {
                "@timestamp": "2026-03-14T12:00:00Z",
                "message": "ipv6 filterlog",
                "host": {"ip": "192.168.1.1"},
                "pfsense": {
                    "ip_version": "6",
                    "column16": "2001:da8:204:2103:0:27:42ef:dfc2",
                    "column17": "2409:8754:1410:800a::e68",
                    "column18": "28810",
                    "column19": "45027",
                },
            },
        }

        event = extract_event(hit)

        self.assertEqual(event["source_ip"], "2001:da8:204:2103:0:27:42ef:dfc2")
        self.assertEqual(event["destination_ip"], "2409:8754:1410:800a::e68")
        self.assertEqual(event["source_port"], 28810)
        self.assertEqual(event["destination_port"], 45027)

    def test_extract_event_prefers_ecs_client_server_fields(self) -> None:
        hit = {
            "_id": "doc-ecs",
            "_index": "nginx-access-2026.03.14",
            "_source": {
                "@timestamp": "2026-03-14T12:00:00Z",
                "event": {"action": "allowed"},
                "client": {"ip": "203.0.113.10", "port": 54321},
                "server": {"ip": "10.0.0.20", "port": 443},
                "message": "GET /index.html",
            },
        }

        event = extract_event(hit)

        self.assertEqual(event["event_action"], "allowed")
        self.assertEqual(event["source_ip"], "203.0.113.10")
        self.assertEqual(event["destination_ip"], "10.0.0.20")
        self.assertEqual(event["source_port"], 54321)
        self.assertEqual(event["destination_port"], 443)

    def test_extract_event_supports_opnsense_alias_fields(self) -> None:
        hit = {
            "_id": "doc-opnsense",
            "_index": "opnsense-2026.03.14",
            "_source": {
                "@timestamp": "2026-03-14T12:00:00Z",
                "event": {"original": "filterlog raw text"},
                "opnsense": {
                    "ip_version": "4",
                    "action": "block",
                    "column19": "192.168.10.20",
                    "column20": "172.16.1.10",
                    "column21": "53210",
                    "column22": "8443",
                },
            },
        }

        event = extract_event(hit)

        self.assertEqual(event["event_action"], "block")
        self.assertEqual(event["source_ip"], "192.168.10.20")
        self.assertEqual(event["destination_ip"], "172.16.1.10")
        self.assertEqual(event["source_port"], 53210)
        self.assertEqual(event["destination_port"], 8443)
        self.assertEqual(event["message"], "filterlog raw text")

    def test_extract_event_supports_waf_style_action_fields(self) -> None:
        hit = {
            "_id": "doc-waf",
            "_index": "waf-2026.03.14",
            "_source": {
                "@timestamp": "2026-03-14T12:00:00Z",
                "client": {"ip": "198.51.100.20"},
                "host": {"ip": ["10.10.10.10"]},
                "server": {"port": 443},
                "rule": {"action": "block", "name": "SQLi rule"},
            },
        }

        event = extract_event(hit)

        self.assertEqual(event["event_action"], "block")
        self.assertEqual(event["source_ip"], "198.51.100.20")
        self.assertEqual(event["destination_ip"], "10.10.10.10")
        self.assertEqual(event["destination_port"], 443)
        self.assertEqual(event["message"], "SQLi rule")

    def test_search_logs_rejects_reversed_time_range(self) -> None:
        settings = make_settings()
        with self.assertRaises(ValidationError):
            search_logs(
                settings,
                source_ip=None,
                destination_ip=None,
                start="2026-03-14T12:00:00Z",
                end="2026-03-14T11:00:00Z",
                size=10,
            )

    def test_fetch_range_events_rejects_reversed_time_range(self) -> None:
        settings = make_settings()
        with self.assertRaises(ValidationError):
            fetch_range_events(
                settings,
                start="2026-03-14T12:00:00Z",
                end="2026-03-14T11:00:00Z",
                size=10,
            )

    def test_search_logs_supports_ip_prefix_mode(self) -> None:
        settings = make_settings()
        captured: dict[str, object] = {}

        class FakeClient:
            def search(self, **kwargs):
                captured.update(kwargs)
                return {"hits": {"total": {"value": 0}, "hits": []}}

        with patch("app.services.es_service.get_es_client", return_value=FakeClient()):
            result = search_logs(
                settings,
                source_ip="192.168",
                destination_ip=None,
                start="2026-03-14T11:00:00Z",
                end="2026-03-14T12:00:00Z",
                size=10,
                source_ip_mode="prefix",
            )

        self.assertEqual(result.total, 0)
        query = captured["query"]
        ip_clause = query["bool"]["must"][1]["bool"]["should"]
        self.assertIn(
            {"range": {"source.ip": {"gte": "192.168.0.0", "lte": "192.168.255.255"}}},
            ip_clause,
        )
        self.assertIn(
            {"range": {"client.ip": {"gte": "192.168.0.0", "lte": "192.168.255.255"}}},
            ip_clause,
        )
        self.assertIn(
            {"prefix": {"pfsense.column16": "192.168"}},
            ip_clause,
        )
        self.assertIn(
            {"prefix": {"pfsense.column19": "192.168"}},
            ip_clause,
        )
        self.assertIn(
            {"prefix": {"client.address": "192.168"}},
            ip_clause,
        )

    def test_search_logs_supports_excluded_ip_prefixes(self) -> None:
        settings = make_settings()
        captured: dict[str, object] = {}

        class FakeClient:
            def search(self, **kwargs):
                captured.update(kwargs)
                return {"hits": {"total": {"value": 0}, "hits": []}}

        with patch("app.services.es_service.get_es_client", return_value=FakeClient()):
            search_logs(
                settings,
                source_ip=None,
                destination_ip=None,
                start="2026-03-14T11:00:00Z",
                end="2026-03-14T12:00:00Z",
                size=10,
                exclude_source_ip_prefixes=["192", "10.0"],
            )

        must_not = captured["query"]["bool"]["must_not"]
        self.assertEqual(len(must_not), 2)
        self.assertIn({"prefix": {"pfsense.column19": "192"}}, must_not[0]["bool"]["should"])
        self.assertIn({"range": {"client.ip": {"gte": "192.0.0.0", "lte": "192.255.255.255"}}}, must_not[0]["bool"]["should"])

    def test_search_logs_rejects_invalid_ip_prefix(self) -> None:
        settings = make_settings()
        with self.assertRaises(ValidationError):
            search_logs(
                settings,
                source_ip="192.168.ab",
                destination_ip=None,
                start="2026-03-14T11:00:00Z",
                end="2026-03-14T12:00:00Z",
                size=10,
                source_ip_mode="prefix",
            )

    def test_search_logs_supports_destination_ip_prefix_mode(self) -> None:
        settings = make_settings()
        captured: dict[str, object] = {}

        class FakeClient:
            def search(self, **kwargs):
                captured.update(kwargs)
                return {"hits": {"total": {"value": 0}, "hits": []}}

        with patch("app.services.es_service.get_es_client", return_value=FakeClient()):
            search_logs(
                settings,
                source_ip=None,
                destination_ip="10.0",
                start="2026-03-14T11:00:00Z",
                end="2026-03-14T12:00:00Z",
                size=10,
                destination_ip_mode="prefix",
            )

        ip_clause = captured["query"]["bool"]["must"][1]["bool"]["should"]
        self.assertIn(
            {"range": {"destination.ip": {"gte": "10.0.0.0", "lte": "10.0.255.255"}}},
            ip_clause,
        )
        self.assertIn(
            {"range": {"server.ip": {"gte": "10.0.0.0", "lte": "10.0.255.255"}}},
            ip_clause,
        )
        self.assertIn(
            {"prefix": {"pfsense.column20": "10.0"}},
            ip_clause,
        )
        self.assertIn(
            {"prefix": {"server.address": "10.0"}},
            ip_clause,
        )

    def test_search_logs_supports_pagination(self) -> None:
        settings = make_settings()
        captured: dict[str, object] = {}

        class FakeClient:
            def search(self, **kwargs):
                captured.update(kwargs)
                return {
                    "hits": {
                        "total": {"value": 25},
                        "hits": [],
                    }
                }

        with patch("app.services.es_service.get_es_client", return_value=FakeClient()):
            result = search_logs(
                settings,
                source_ip=None,
                destination_ip=None,
                start="2026-03-14T11:00:00Z",
                end="2026-03-14T12:00:00Z",
                size=10,
                page=3,
            )

        self.assertEqual(captured["from_"], 20)
        self.assertEqual(captured["sort"], [{"@timestamp": {"order": "desc"}}])
        self.assertEqual(result.page, 3)
        self.assertEqual(result.size, 10)
        self.assertEqual(result.total_pages, 3)
        self.assertTrue(result.has_prev)
        self.assertFalse(result.has_next)

    def test_fetch_range_events_uses_point_in_time_pagination(self) -> None:
        settings = replace(make_settings(), es_search_batch_size=2)

        class FakeClient:
            def __init__(self) -> None:
                self.search_calls: list[dict[str, object]] = []
                self.closed_pit_id: str | None = None

            def open_point_in_time(self, **kwargs):
                self.open_kwargs = kwargs
                return {"id": "pit-123"}

            def search(self, **kwargs):
                self.search_calls.append(kwargs)
                if len(self.search_calls) == 1:
                    return {
                        "hits": {
                            "hits": [
                                {
                                    "_id": "doc-1",
                                    "_index": "pfsense-2026.03.14",
                                    "_source": {
                                        "@timestamp": "2026-03-14T12:00:00Z",
                                        "event": {"action": "block"},
                                        "message": "blocked traffic",
                                    },
                                    "sort": ["2026-03-14T12:00:00Z", 7],
                                },
                                {
                                    "_id": "doc-2",
                                    "_index": "pfsense-2026.03.14",
                                    "_source": {
                                        "@timestamp": "2026-03-14T11:59:59Z",
                                        "event": {"action": "block"},
                                        "message": "blocked traffic again",
                                    },
                                    "sort": ["2026-03-14T11:59:59Z", 6],
                                }
                            ]
                        }
                    }
                return {"hits": {"hits": []}}

            def close_point_in_time(self, **kwargs):
                self.closed_pit_id = kwargs["id"]

        client = FakeClient()
        with patch("app.services.es_service.get_es_client", return_value=client):
            events, truncated = fetch_range_events(
                settings,
                start="2026-03-14T11:00:00Z",
                end="2026-03-14T12:00:00Z",
                size=10,
            )

        self.assertFalse(truncated)
        self.assertEqual(len(events), 2)
        self.assertEqual(client.open_kwargs["index"], "pfsense-*")
        self.assertEqual(client.open_kwargs["keep_alive"], "1m")
        self.assertNotIn("index", client.search_calls[0])
        self.assertEqual(
            client.search_calls[0]["sort"],
            [{"@timestamp": {"order": "desc"}}, {"_shard_doc": {"order": "desc"}}],
        )
        self.assertEqual(client.search_calls[0]["pit"], {"id": "pit-123", "keep_alive": "1m"})
        self.assertEqual(client.search_calls[1]["search_after"], ["2026-03-14T11:59:59Z", 6])
        self.assertEqual(client.closed_pit_id, "pit-123")

    def test_fetch_range_events_falls_back_when_point_in_time_unavailable(self) -> None:
        settings = make_settings()

        class FakeClient:
            def __init__(self) -> None:
                self.search_calls: list[dict[str, object]] = []

            def open_point_in_time(self, **kwargs):
                raise RuntimeError("pit disabled")

            def search(self, **kwargs):
                self.search_calls.append(kwargs)
                return {"hits": {"hits": []}}

            def close_point_in_time(self, **kwargs):
                raise AssertionError("close_point_in_time should not be called without PIT")

        client = FakeClient()
        with patch("app.services.es_service.get_es_client", return_value=client):
            events, truncated = fetch_range_events(
                settings,
                start="2026-03-14T11:00:00Z",
                end="2026-03-14T12:00:00Z",
                size=10,
            )

        self.assertEqual(events, [])
        self.assertFalse(truncated)
        self.assertEqual(
            client.search_calls[0]["sort"],
            [{"@timestamp": {"order": "desc"}}],
        )
        self.assertEqual(client.search_calls[0]["index"], "pfsense-*")
        self.assertNotIn("pit", client.search_calls[0])

    def test_delete_logs_before_calls_delete_by_query(self) -> None:
        settings = make_settings()
        captured: dict[str, object] = {}

        class FakeClient:
            def delete_by_query(self, **kwargs):
                captured.update(kwargs)
                return {
                    "total": 5,
                    "deleted": 5,
                    "batches": 1,
                    "version_conflicts": 0,
                    "failures": [],
                }

        with patch("app.services.es_service.get_es_client", return_value=FakeClient()):
            result = delete_logs_before(
                settings,
                before="2026-03-14T12:00:00Z",
                ip="192.168",
                ip_mode="prefix",
            )

        self.assertEqual(result["deleted"], 5)
        self.assertEqual(captured["conflicts"], "proceed")
        self.assertTrue(captured["refresh"])
        self.assertTrue(captured["wait_for_completion"])
        ip_clause = captured["query"]["bool"]["must"][1]["bool"]["should"]
        self.assertIn(
            {"range": {"source.ip": {"gte": "192.168.0.0", "lte": "192.168.255.255"}}},
            ip_clause,
        )


if __name__ == "__main__":
    unittest.main()
