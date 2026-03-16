import unittest
import sys
import types
from unittest.mock import patch

fake_elasticsearch = types.ModuleType("elasticsearch")
fake_elasticsearch.Elasticsearch = object
sys.modules.setdefault("elasticsearch", fake_elasticsearch)

fake_openai = types.ModuleType("openai")
fake_openai.OpenAI = object
sys.modules.setdefault("openai", fake_openai)

from app.config import Settings
from app.services.detection_service import build_detection_report


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
        suspicious_threshold=2,
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


class DetectionServiceTests(unittest.TestCase):
    @patch("app.services.detection_service.summarize_with_qwen", return_value="summary")
    @patch("app.services.detection_service.fetch_window_events")
    def test_build_detection_report_deduplicates_reasons(
        self,
        mock_fetch_window_events,
        _mock_summarize,
    ) -> None:
        settings = make_settings()
        mock_fetch_window_events.return_value = (
            [
                {
                    "timestamp": "2026-03-14T12:00:00Z",
                    "event_action": "block",
                    "source_ip": "1.1.1.1",
                    "destination_ip": "2.2.2.2",
                    "destination_port": 3389,
                    "message": "blocked risky port",
                },
                {
                    "timestamp": "2026-03-14T12:01:00Z",
                    "event_action": "pass",
                    "source_ip": "9.9.9.9",
                    "destination_ip": "3.3.3.3",
                    "destination_port": 443,
                    "message": "normal traffic",
                },
            ],
            False,
        )

        report = build_detection_report(settings, minutes=10)

        self.assertEqual(report["suspicious_count"], 1)
        self.assertEqual(report["alerts"][0]["severity"], "high")
        self.assertEqual(
            report["alerts"][0]["reasons"],
            ["blocked_traffic", "risky_destination_port"],
        )

    @patch("app.services.detection_service.summarize_with_qwen", return_value="summary")
    @patch("app.services.detection_service.fetch_window_events")
    def test_build_detection_report_adds_high_frequency_alert(
        self,
        mock_fetch_window_events,
        _mock_summarize,
    ) -> None:
        settings = make_settings()
        mock_fetch_window_events.return_value = (
            [
                {
                    "timestamp": "2026-03-14T12:00:00Z",
                    "event_action": "pass",
                    "source_ip": "7.7.7.7",
                    "destination_ip": "2.2.2.2",
                    "destination_port": 80,
                    "message": "one",
                },
                {
                    "timestamp": "2026-03-14T12:01:00Z",
                    "event_action": "pass",
                    "source_ip": "7.7.7.7",
                    "destination_ip": "2.2.2.3",
                    "destination_port": 443,
                    "message": "two",
                },
            ],
            False,
        )

        report = build_detection_report(settings, minutes=10)

        self.assertEqual(report["suspicious_count"], 1)
        self.assertEqual(report["alerts"][0]["type"], "aggregate")
        self.assertEqual(report["alerts"][0]["source_ip"], "7.7.7.7")
        self.assertEqual(report["alerts"][0]["event_count"], 2)

    @patch("app.services.detection_service.summarize_with_qwen", return_value="summary")
    @patch("app.services.detection_service.fetch_window_events")
    def test_build_detection_report_applies_exclusion_rules(
        self,
        mock_fetch_window_events,
        _mock_summarize,
    ) -> None:
        settings = make_settings()
        mock_fetch_window_events.return_value = (
            [
                {
                    "timestamp": "2026-03-14T12:00:00Z",
                    "event_action": "block",
                    "source_ip": "1.1.1.1",
                    "destination_ip": "8.8.8.8",
                    "destination_port": 3389,
                    "message": "blocked risky port",
                },
                {
                    "timestamp": "2026-03-14T12:01:00Z",
                    "event_action": "pass",
                    "source_ip": "2.2.2.2",
                    "destination_ip": "172.16.0.3",
                    "destination_port": 22,
                    "message": "normal traffic",
                },
                {
                    "timestamp": "2026-03-14T12:02:00Z",
                    "event_action": "alert",
                    "source_ip": "3.3.3.3",
                    "destination_ip": "9.9.9.9",
                    "destination_port": 22,
                    "message": "healthcheck whitelist event",
                },
            ],
            False,
        )

        report = build_detection_report(
            settings,
            minutes=10,
            exclude_event_actions=["block"],
            exclude_destination_ip_prefixes=["172.16"],
            exclude_message_keywords=["whitelist"],
        )

        self.assertEqual(report["total_logs"], 0)
        self.assertEqual(report["excluded_logs"], 3)
        self.assertEqual(report["suspicious_count"], 0)
        self.assertEqual(report["message"], "检测完成，已按自动分析规则排除 3 条日志。")


if __name__ == "__main__":
    unittest.main()
