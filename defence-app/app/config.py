import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_ports(name: str, default: str) -> frozenset[int]:
    raw_value = os.getenv(name, default)
    return frozenset(
        int(item.strip()) for item in raw_value.split(",") if item.strip().isdigit()
    )


@dataclass(frozen=True)
class Settings:
    es_url: str
    es_index_pattern: str
    es_username: str | None
    es_password: str | None
    es_timeout_seconds: int
    es_search_batch_size: int
    detection_max_logs: int
    qwen_api_key: str | None
    qwen_base_url: str
    qwen_model: str
    ai_timeout_seconds: int
    detection_window_minutes: int
    suspicious_threshold: int
    risky_ports: frozenset[int]
    max_alerts_display: int
    auto_refresh_seconds: int
    enable_scheduler: bool
    auth_enabled: bool
    login_email: str
    login_password: str
    session_secret: str
    session_max_age_seconds: int


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        es_url=os.getenv("ES_URL", "http://127.0.0.1:9200"),
        es_index_pattern=os.getenv("ES_INDEX_PATTERN", "pfsense-*"),
        es_username=os.getenv("ES_USERNAME"),
        es_password=os.getenv("ES_PASSWORD"),
        es_timeout_seconds=_get_int("ES_TIMEOUT_SECONDS", 10),
        es_search_batch_size=_get_int("ES_SEARCH_BATCH_SIZE", 500),
        detection_max_logs=_get_int("DETECTION_MAX_LOGS", 10000),
        qwen_api_key=os.getenv("QWEN_API_KEY"),
        qwen_base_url=os.getenv(
            "QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"
        ),
        qwen_model=os.getenv("QWEN_MODEL", "qwen-plus"),
        ai_timeout_seconds=_get_int("AI_TIMEOUT_SECONDS", 30),
        detection_window_minutes=_get_int("DETECTION_WINDOW_MINUTES", 10),
        suspicious_threshold=_get_int("SUSPICIOUS_THRESHOLD", 20),
        risky_ports=_get_ports("RISKY_PORTS", "22,23,3389,445,1433,3306"),
        max_alerts_display=_get_int("MAX_ALERTS_DISPLAY", 200),
        auto_refresh_seconds=_get_int("AUTO_REFRESH_SECONDS", 60),
        enable_scheduler=_get_bool("ENABLE_SCHEDULER", True),
        auth_enabled=_get_bool("AUTH_ENABLED", True),
        login_email=os.getenv("LOGIN_EMAIL", "admin@example.com").strip(),
        login_password=os.getenv("LOGIN_PASSWORD", "ChangeMe123!"),
        session_secret=os.getenv("SESSION_SECRET", "defence-app-dev-secret"),
        session_max_age_seconds=_get_int("SESSION_MAX_AGE_SECONDS", 86400),
    )
