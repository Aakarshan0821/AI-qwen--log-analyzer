import os
import sys
import types
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

os.environ["ENABLE_SCHEDULER"] = "false"
os.environ["AUTH_ENABLED"] = "false"

fake_elasticsearch = types.ModuleType("elasticsearch")
fake_elasticsearch.Elasticsearch = object
sys.modules.setdefault("elasticsearch", fake_elasticsearch)

fake_openai = types.ModuleType("openai")
fake_openai.OpenAI = object
sys.modules.setdefault("openai", fake_openai)

from app.app_factory import create_app


class RouteTests(unittest.TestCase):
    def test_auto_analysis_settings_endpoints(self) -> None:
        with TestClient(create_app()) as client:
            with patch(
                "app.api.routes.save_auto_analysis_config",
                return_value={
                    "enabled": True,
                    "interval_minutes": 15,
                    "exclude_source_ip_prefixes": ["192.168"],
                    "exclude_destination_ip_prefixes": [],
                    "exclude_event_actions": ["block"],
                    "exclude_message_keywords": ["healthcheck"],
                },
            ):
                with patch(
                    "app.api.routes.sync_auto_analysis_scheduler",
                    new=AsyncMock(),
                ) as mocked_sync:
                    response = client.post(
                        "/api/auto-analysis/settings",
                        json={
                            "enabled": True,
                            "interval_minutes": 15,
                            "exclude_source_ip_prefixes": ["192.168"],
                            "exclude_destination_ip_prefixes": [],
                            "exclude_event_actions": ["block"],
                            "exclude_message_keywords": ["healthcheck"],
                        },
                    )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["enabled"], True)
        self.assertEqual(payload["interval_minutes"], 15)
        self.assertEqual(payload["exclude_source_ip_prefixes"], ["192.168"])
        self.assertEqual(payload["exclude_event_actions"], ["block"])
        mocked_sync.assert_awaited_once()

    def test_search_endpoint_supports_pagination(self) -> None:
        with TestClient(create_app()) as client:
            with patch(
                "app.api.routes.search_logs",
                return_value={
                    "total": 25,
                    "page": 2,
                    "size": 10,
                    "total_pages": 3,
                    "has_prev": True,
                    "has_next": True,
                    "logs": [],
                },
            ) as mocked_search:
                response = client.get("/api/search?page=2&size=10")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["page"], 2)
        self.assertEqual(payload["total_pages"], 3)
        mocked_search.assert_called_once()
        self.assertEqual(mocked_search.call_args.kwargs["page"], 2)
        self.assertEqual(mocked_search.call_args.kwargs["size"], 10)

    def test_delete_logs_before_endpoint(self) -> None:
        with TestClient(create_app()) as client:
            with patch(
                "app.api.routes.delete_logs_before",
                return_value={
                    "before": "2026-03-14T12:00:00+00:00",
                    "matched": 12,
                    "deleted": 12,
                    "batches": 1,
                    "version_conflicts": 0,
                    "ip": "192.168",
                    "ip_mode": "prefix",
                },
            ):
                response = client.post(
                    "/api/logs/delete-before",
                    json={
                        "before": "2026-03-14T12:00:00Z",
                        "ip": "192.168",
                        "ip_mode": "prefix",
                    },
                )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["deleted"], 12)
        self.assertIn("192.168", payload["message"])

    def test_ai_analyze_selected_endpoint(self) -> None:
        with TestClient(create_app()) as client:
            with patch("app.api.routes.summarize_logs_with_qwen", return_value="selected summary"):
                response = client.post(
                    "/api/ai/analyze/selected",
                    json={
                        "selected_logs": [
                            {
                                "timestamp": "2026-03-14T12:00:00Z",
                                "event_action": "block",
                                "source_ip": "1.1.1.1",
                                "destination_ip": "2.2.2.2",
                                "destination_port": 3389,
                                "message": "blocked traffic",
                            }
                        ]
                    },
                )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["analysis_type"], "selected")
        self.assertEqual(payload["summary"], "selected summary")
        self.assertEqual(payload["total_logs"], 1)

    def test_ai_analyze_range_endpoint(self) -> None:
        with TestClient(create_app()) as client:
            with patch(
                "app.api.routes.search_logs",
                return_value=types.SimpleNamespace(
                    total=1,
                    logs=[
                        types.SimpleNamespace(
                            model_dump=lambda: {
                                "timestamp": "2026-03-14T12:00:00Z",
                                "event_action": "block",
                                "source_ip": "1.1.1.1",
                                "destination_ip": "2.2.2.2",
                                "destination_port": 3389,
                                "message": "blocked traffic",
                                "raw": {"message": "blocked traffic"},
                            }
                        )
                    ],
                ),
            ):
                with patch("app.api.routes.summarize_logs_with_qwen", return_value="range summary"):
                    response = client.post(
                        "/api/ai/analyze/range",
                        json={
                            "start": "2026-03-14T11:00:00Z",
                            "end": "2026-03-14T12:00:00Z",
                            "size": 100,
                            "source_ip": "192.168",
                            "source_ip_mode": "prefix",
                            "destination_ip": "10.0.0.5",
                            "destination_ip_mode": "exact",
                            "exclude_source_ip_prefixes": ["10"],
                        },
                    )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["analysis_type"], "range")
        self.assertEqual(payload["summary"], "range summary")
        self.assertEqual(payload["total_logs"], 1)
        self.assertEqual(payload["requested_source_ip"], "192.168")
        self.assertEqual(payload["requested_destination_ip"], "10.0.0.5")
        self.assertEqual(payload["excluded_source_ip_prefixes"], ["10"])
        self.assertEqual(len(payload["logs"]), 1)


if __name__ == "__main__":
    unittest.main()
