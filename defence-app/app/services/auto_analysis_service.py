import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI

from app.config import Settings
from app.schemas import AutoAnalysisSettingsRequest
from app.services.detection_service import build_detection_report
from app.state import make_idle_detection, set_detection_error, set_latest_detection

logger = logging.getLogger(__name__)

AUTO_ANALYSIS_JOB_ID = "suspicious_detection"
AUTO_ANALYSIS_SETTINGS_PATH = Path.home() / ".defence-app" / "auto_analysis_settings.json"
MAX_AUTO_ANALYSIS_FILTER_ITEMS = 20


def _normalize_tokens(values: Iterable[Any] | None, *, lower: bool = False) -> List[str]:
    normalized: List[str] = []
    seen: set[str] = set()

    for item in values or []:
        token = str(item or "").strip()
        if not token:
            continue
        if lower:
            token = token.lower()
        if token in seen:
            continue
        seen.add(token)
        normalized.append(token)
        if len(normalized) >= MAX_AUTO_ANALYSIS_FILTER_ITEMS:
            break

    return normalized


def _default_auto_analysis_config(settings: Settings) -> Dict[str, Any]:
    return {
        "enabled": settings.enable_scheduler,
        "interval_minutes": settings.detection_window_minutes,
        "exclude_source_ip_prefixes": [],
        "exclude_destination_ip_prefixes": [],
        "exclude_event_actions": [],
        "exclude_message_keywords": [],
    }


def normalize_auto_analysis_config(
    settings: Settings,
    raw_config: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    defaults = _default_auto_analysis_config(settings)
    config = raw_config or {}

    try:
        interval_minutes = int(config.get("interval_minutes", defaults["interval_minutes"]))
    except (TypeError, ValueError):
        interval_minutes = defaults["interval_minutes"]

    interval_minutes = max(1, min(1440, interval_minutes))

    return {
        "enabled": bool(config.get("enabled", defaults["enabled"])),
        "interval_minutes": interval_minutes,
        "exclude_source_ip_prefixes": _normalize_tokens(
            config.get("exclude_source_ip_prefixes"),
        ),
        "exclude_destination_ip_prefixes": _normalize_tokens(
            config.get("exclude_destination_ip_prefixes"),
        ),
        "exclude_event_actions": _normalize_tokens(
            config.get("exclude_event_actions"),
            lower=True,
        ),
        "exclude_message_keywords": _normalize_tokens(
            config.get("exclude_message_keywords"),
            lower=True,
        ),
    }


def load_auto_analysis_config(settings: Settings) -> Dict[str, Any]:
    if not AUTO_ANALYSIS_SETTINGS_PATH.exists():
        return _default_auto_analysis_config(settings)

    try:
        raw_config = json.loads(AUTO_ANALYSIS_SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("Failed to read auto analysis settings, using defaults.")
        return _default_auto_analysis_config(settings)

    return normalize_auto_analysis_config(settings, raw_config)


def save_auto_analysis_config(
    settings: Settings,
    payload: AutoAnalysisSettingsRequest,
) -> Dict[str, Any]:
    config = normalize_auto_analysis_config(settings, payload.model_dump())
    AUTO_ANALYSIS_SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    AUTO_ANALYSIS_SETTINGS_PATH.write_text(
        json.dumps(config, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return config


def get_auto_analysis_config(app: FastAPI) -> Dict[str, Any]:
    config = getattr(app.state, "auto_analysis_config", None)
    if isinstance(config, dict):
        return dict(config)

    loaded_config = load_auto_analysis_config(app.state.settings)
    app.state.auto_analysis_config = loaded_config
    return dict(loaded_config)


def _build_auto_analysis_response(
    app: FastAPI,
    config: Dict[str, Any],
    *,
    message: str,
) -> Dict[str, Any]:
    scheduler: AsyncIOScheduler = app.state.scheduler
    job = scheduler.get_job(AUTO_ANALYSIS_JOB_ID)
    return {
        "status": "ok",
        "message": message,
        **config,
        "scheduler_running": bool(scheduler.running),
        "job_registered": job is not None,
    }


def get_auto_analysis_settings_response(
    app: FastAPI,
    *,
    message: str = "自动分析设置已加载。",
) -> Dict[str, Any]:
    return _build_auto_analysis_response(app, get_auto_analysis_config(app), message=message)


def _set_disabled_detection_state(config: Dict[str, Any]) -> None:
    report = make_idle_detection(config["interval_minutes"])
    report["message"] = "AI 自动分析已关闭。"
    report["auto_analysis_settings"] = dict(config)
    set_latest_detection(report)


async def run_auto_analysis_job(app: FastAPI) -> None:
    settings: Settings = app.state.settings
    config = get_auto_analysis_config(app)

    if not config["enabled"]:
        _set_disabled_detection_state(config)
        return

    try:
        report = build_detection_report(
            settings,
            minutes=config["interval_minutes"],
            exclude_source_ip_prefixes=config["exclude_source_ip_prefixes"],
            exclude_destination_ip_prefixes=config["exclude_destination_ip_prefixes"],
            exclude_event_actions=config["exclude_event_actions"],
            exclude_message_keywords=config["exclude_message_keywords"],
        )
    except Exception as exc:  # pragma: no cover
        logger.exception("Auto analysis job failed", exc_info=exc)
        error_report = set_detection_error(
            f"定时检测失败：{type(exc).__name__}",
            config["interval_minutes"],
        )
        error_report["auto_analysis_settings"] = dict(config)
        set_latest_detection(error_report)
        return

    report["auto_analysis_settings"] = dict(config)
    set_latest_detection(report)


async def sync_auto_analysis_scheduler(
    app: FastAPI,
    *,
    run_immediately: bool = False,
) -> None:
    scheduler: AsyncIOScheduler = app.state.scheduler
    config = get_auto_analysis_config(app)

    if scheduler.get_job(AUTO_ANALYSIS_JOB_ID):
        scheduler.remove_job(AUTO_ANALYSIS_JOB_ID)

    if config["enabled"]:
        scheduler.add_job(
            run_auto_analysis_job,
            "interval",
            minutes=config["interval_minutes"],
            args=[app],
            id=AUTO_ANALYSIS_JOB_ID,
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        if not scheduler.running:
            scheduler.start()
        if run_immediately:
            await run_auto_analysis_job(app)
        return

    if run_immediately:
        _set_disabled_detection_state(config)
