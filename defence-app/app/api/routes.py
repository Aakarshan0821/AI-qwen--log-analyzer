from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Form, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.auth import SESSION_COOKIE_NAME, create_session_token, verify_session_token
from app.config import Settings
from app.schemas import (
    AutoAnalysisSettingsRequest,
    DeleteLogsRequest,
    SelectedLogAnalysisRequest,
    TimeRangeAnalysisRequest,
)
from app.services.auto_analysis_service import (
    get_auto_analysis_config,
    get_auto_analysis_settings_response,
    save_auto_analysis_config,
    sync_auto_analysis_scheduler,
)
from app.services.ai_service import (
    get_ai_config_status,
    send_test_message,
    summarize_logs_with_qwen,
)
from app.services.detection_service import build_detection_report
from app.services.es_service import check_es_health, delete_logs_before, search_logs
from app.state import get_latest_detection, set_latest_detection

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


def _get_settings(request: Request) -> Settings:
    return request.app.state.settings


def _get_login_page_context(request: Request, error_message: str = "") -> Dict[str, Any]:
    return {
        "request": request,
        "error_message": error_message,
        "asset_version": request.app.version,
    }


def _is_authenticated(request: Request) -> bool:
    settings = _get_settings(request)
    if not settings.auth_enabled:
        return True

    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return False

    email = verify_session_token(token, settings.session_secret)
    return bool(email)


def _require_api_auth(request: Request) -> None:
    if _is_authenticated(request):
        return
    raise HTTPException(status_code=401, detail="未登录或登录已过期，请重新登录。")


def _set_session_cookie(
    response: Response,
    request: Request,
    settings: Settings,
    remember_for_30_days: bool,
) -> None:
    max_age = settings.session_max_age_seconds * 30 if remember_for_30_days else settings.session_max_age_seconds
    token = create_session_token(settings.login_email, settings.session_secret, max_age)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=max_age,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        path="/",
    )


def _split_csv_values(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    if _is_authenticated(request):
        return RedirectResponse(url="/", status_code=303)

    error_message = request.query_params.get("error", "")
    return templates.TemplateResponse("login.html", _get_login_page_context(request, error_message=error_message))


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    remember: Optional[str] = Form(default=None),
) -> Response:
    settings = _get_settings(request)
    remember_for_30_days = remember == "on"
    if email == settings.login_email and password == settings.login_password:
        response = RedirectResponse(url="/", status_code=303)
        _set_session_cookie(response, request, settings, remember_for_30_days=remember_for_30_days)
        return response

    return templates.TemplateResponse(
        "login.html",
        _get_login_page_context(request, error_message="账号或密码错误，请重试。"),
        status_code=401,
    )


@router.post("/logout")
async def logout(request: Request) -> Response:
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response


@router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    if not _is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)

    settings = _get_settings(request)
    auto_analysis_config = get_auto_analysis_config(request.app)
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "auto_refresh_seconds": settings.auto_refresh_seconds,
            "default_window_minutes": auto_analysis_config["interval_minutes"],
            "asset_version": request.app.version,
        },
    )


@router.get("/api/search")
async def api_search(
    request: Request,
    source_ip: Optional[str] = Query(default=None, description="来源 IP"),
    source_ip_mode: Literal["exact", "prefix"] = Query(default="exact", description="来源 IP 匹配方式"),
    destination_ip: Optional[str] = Query(default=None, description="目标 IP"),
    destination_ip_mode: Literal["exact", "prefix"] = Query(default="exact", description="目标 IP 匹配方式"),
    exclude_source_ip_prefixes: Optional[str] = Query(default=None, description="逗号分隔的屏蔽来源 IP 前缀"),
    start: Optional[str] = Query(default=None, description="开始时间 ISO8601"),
    end: Optional[str] = Query(default=None, description="结束时间 ISO8601"),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=200, ge=1, le=1000),
):
    _require_api_auth(request)
    return search_logs(
        _get_settings(request),
        source_ip=source_ip,
        source_ip_mode=source_ip_mode,
        destination_ip=destination_ip,
        destination_ip_mode=destination_ip_mode,
        exclude_source_ip_prefixes=_split_csv_values(exclude_source_ip_prefixes),
        start=start,
        end=end,
        page=page,
        size=size,
    )


@router.post("/api/logs/delete-before")
async def api_delete_logs_before(
    request: Request,
    payload: DeleteLogsRequest,
) -> Dict[str, Any]:
    _require_api_auth(request)
    result = delete_logs_before(
        _get_settings(request),
        before=payload.before,
        ip=payload.ip,
        ip_mode=payload.ip_mode,
    )
    filter_desc = ""
    if result["ip"]:
        match_label = "前缀" if result["ip_mode"] == "prefix" else "精确 IP"
        filter_desc = f"（筛选 {match_label}：{result['ip']}）"
    return {
        "status": "ok",
        "before": result["before"],
        "matched": result["matched"],
        "deleted": result["deleted"],
        "batches": result["batches"],
        "version_conflicts": result["version_conflicts"],
        "message": f"已删除 {result['deleted']} 条 {result['before']} 之前的日志{filter_desc}。",
    }


@router.post("/api/detect/manual")
async def api_manual_detect(
    request: Request, minutes: Optional[int] = Query(default=None, ge=1, le=1440)
) -> Dict[str, Any]:
    _require_api_auth(request)
    auto_analysis_config = get_auto_analysis_config(request.app)
    report = build_detection_report(
        _get_settings(request),
        minutes=minutes or auto_analysis_config["interval_minutes"],
        exclude_source_ip_prefixes=auto_analysis_config["exclude_source_ip_prefixes"],
        exclude_destination_ip_prefixes=auto_analysis_config["exclude_destination_ip_prefixes"],
        exclude_event_actions=auto_analysis_config["exclude_event_actions"],
        exclude_message_keywords=auto_analysis_config["exclude_message_keywords"],
    )
    report["auto_analysis_settings"] = auto_analysis_config
    set_latest_detection(report)
    return report


@router.get("/api/detect/latest")
async def api_latest_detect(request: Request) -> Dict[str, Any]:
    _require_api_auth(request)
    auto_analysis_config = get_auto_analysis_config(request.app)
    report = get_latest_detection(auto_analysis_config["interval_minutes"])
    report.setdefault("auto_analysis_settings", auto_analysis_config)
    return report


@router.get("/api/auto-analysis/settings")
async def api_auto_analysis_settings(request: Request) -> Dict[str, Any]:
    _require_api_auth(request)
    return get_auto_analysis_settings_response(request.app)


@router.post("/api/auto-analysis/settings")
async def api_update_auto_analysis_settings(
    request: Request,
    payload: AutoAnalysisSettingsRequest,
) -> Dict[str, Any]:
    _require_api_auth(request)
    config = save_auto_analysis_config(_get_settings(request), payload)
    request.app.state.auto_analysis_config = config
    await sync_auto_analysis_scheduler(request.app, run_immediately=True)
    return get_auto_analysis_settings_response(
        request.app,
        message="自动分析设置已保存，并已按新配置刷新分析任务。",
    )


@router.get("/api/ai/status")
async def api_ai_status(request: Request) -> Dict[str, Any]:
    _require_api_auth(request)
    return get_ai_config_status(_get_settings(request))


@router.post("/api/ai/test")
async def api_ai_test(
    request: Request,
    message: Optional[str] = Query(default=None, description="测试消息"),
) -> Dict[str, Any]:
    _require_api_auth(request)
    return send_test_message(_get_settings(request), message=message)


@router.post("/api/ai/analyze/range")
async def api_ai_analyze_range(
    request: Request,
    payload: TimeRangeAnalysisRequest,
) -> Dict[str, Any]:
    _require_api_auth(request)
    settings = _get_settings(request)
    search_result = search_logs(
        settings,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        start=payload.start,
        end=payload.end,
        size=payload.size,
        source_ip_mode=payload.source_ip_mode,
        destination_ip_mode=payload.destination_ip_mode,
        exclude_source_ip_prefixes=payload.exclude_source_ip_prefixes,
    )
    events = [item.model_dump() if hasattr(item, "model_dump") else item.dict() for item in search_result.logs]
    truncated = search_result.total > len(events)
    summary = summarize_logs_with_qwen(
        settings,
        events,
        analysis_label="自定义时间分析",
        truncated=truncated,
    )
    return {
        "status": "ok",
        "analysis_type": "range",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "requested_start": payload.start,
        "requested_end": payload.end,
        "requested_source_ip": payload.source_ip,
        "requested_source_ip_mode": payload.source_ip_mode,
        "requested_destination_ip": payload.destination_ip,
        "requested_destination_ip_mode": payload.destination_ip_mode,
        "excluded_source_ip_prefixes": payload.exclude_source_ip_prefixes,
        "total_logs": len(events),
        "logs_truncated": truncated,
        "logs": events,
        "summary": summary,
        "message": "自定义时间分析完成。",
    }


@router.post("/api/ai/analyze/selected")
async def api_ai_analyze_selected(
    request: Request,
    payload: SelectedLogAnalysisRequest,
) -> Dict[str, Any]:
    _require_api_auth(request)
    settings = _get_settings(request)
    selected_logs = [
        item.model_dump() if hasattr(item, "model_dump") else item.dict()
        for item in payload.selected_logs
    ]
    summary = summarize_logs_with_qwen(
        settings,
        selected_logs,
        analysis_label="已选日志分析",
        truncated=False,
    )
    return {
        "status": "ok",
        "analysis_type": "selected",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "total_logs": len(selected_logs),
        "logs_truncated": False,
        "summary": summary,
        "message": "已选日志分析完成。",
    }


@router.get("/api/health")
async def api_health(request: Request) -> Dict[str, Any]:
    _require_api_auth(request)
    settings = _get_settings(request)
    auto_analysis_status = get_auto_analysis_settings_response(request.app, message="")
    es_health = check_es_health(settings)
    status = "ok" if es_health["status"] == "up" else "degraded"
    return {
        "status": status,
        "services": {
            "elasticsearch": es_health,
            "ai": get_ai_config_status(settings),
            "scheduler": {
                "status": "enabled" if auto_analysis_status["enabled"] else "disabled",
                "running": auto_analysis_status["scheduler_running"],
                "interval_minutes": auto_analysis_status["interval_minutes"],
                "job_registered": auto_analysis_status["job_registered"],
            },
        },
    }
