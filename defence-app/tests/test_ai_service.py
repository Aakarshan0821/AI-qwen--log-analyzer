import sys
import types
import unittest
from unittest.mock import Mock, patch

fake_openai = types.ModuleType("openai")
fake_openai.OpenAI = object
sys.modules.setdefault("openai", fake_openai)

from app.config import Settings
from app.errors import ExternalServiceError
from app.services.ai_service import (
    get_ai_config_status,
    send_test_message,
    summarize_logs_with_qwen,
)


def make_settings(api_key: str | None = "demo-key") -> Settings:
    return Settings(
        es_url="http://127.0.0.1:9200",
        es_index_pattern="pfsense-*",
        es_username=None,
        es_password=None,
        es_timeout_seconds=10,
        es_search_batch_size=500,
        detection_max_logs=10000,
        qwen_api_key=api_key,
        qwen_base_url="https://example.com",
        qwen_model="qwen-test",
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


class AIServiceTests(unittest.TestCase):
    def test_get_ai_config_status_when_not_configured(self) -> None:
        status = get_ai_config_status(make_settings(api_key=None))

        self.assertEqual(status["status"], "not_configured")
        self.assertIsNone(status["connected"])

    @patch("app.services.ai_service.OpenAI")
    def test_send_test_message_returns_ai_reply(self, mock_openai: Mock) -> None:
        mock_client = mock_openai.return_value
        mock_client.chat.completions.create.return_value = Mock(
            choices=[Mock(message=Mock(content="AI连接正常"))]
        )

        result = send_test_message(make_settings(), "请回复测试成功")

        self.assertEqual(result["status"], "connected")
        self.assertTrue(result["connected"])
        self.assertEqual(result["response_message"], "AI连接正常")

    def test_send_test_message_requires_api_key(self) -> None:
        with self.assertRaises(ExternalServiceError):
            send_test_message(make_settings(api_key=None))

    def test_summarize_logs_with_qwen_returns_local_summary_without_api_key(self) -> None:
        summary = summarize_logs_with_qwen(
            make_settings(api_key=None),
            [
                {
                    "timestamp": "2026-03-14T12:00:00Z",
                    "event_action": "block",
                    "source_ip": "1.1.1.1",
                    "destination_ip": "2.2.2.2",
                    "destination_port": 3389,
                    "message": "blocked traffic",
                }
            ],
            analysis_label="已选日志分析",
        )

        self.assertIn("已选日志分析", summary)
        self.assertIn("当前未配置 AI", summary)


if __name__ == "__main__":
    unittest.main()
