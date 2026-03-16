from copy import deepcopy
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict

_lock = Lock()
_latest_detection: Dict[str, Any] | None = None


def make_idle_detection(window_minutes: int) -> Dict[str, Any]:
    return {
        "status": "idle",
        "window_minutes": window_minutes,
        "checked_at": None,
        "total_logs": 0,
        "logs_truncated": False,
        "suspicious_count": 0,
        "returned_alerts": 0,
        "alerts": [],
        "ai_summary": "暂无检测结果。",
        "message": "尚未执行检测。",
    }


def initialize_state(window_minutes: int) -> None:
    global _latest_detection
    with _lock:
        if _latest_detection is None:
            _latest_detection = make_idle_detection(window_minutes)


def get_latest_detection(window_minutes: int) -> Dict[str, Any]:
    global _latest_detection
    with _lock:
        if _latest_detection is None:
            _latest_detection = make_idle_detection(window_minutes)
        return deepcopy(_latest_detection)


def set_latest_detection(report: Dict[str, Any]) -> None:
    global _latest_detection
    with _lock:
        _latest_detection = deepcopy(report)


def set_detection_error(message: str, window_minutes: int) -> Dict[str, Any]:
    report = {
        "status": "error",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "window_minutes": window_minutes,
        "total_logs": 0,
        "logs_truncated": False,
        "suspicious_count": 0,
        "returned_alerts": 0,
        "alerts": [],
        "ai_summary": "检测失败，请检查 Elasticsearch 或 AI 配置。",
        "message": message,
    }
    set_latest_detection(report)
    return report
