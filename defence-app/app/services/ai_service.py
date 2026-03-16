import json
from collections import Counter
from typing import Any, Dict, List, Optional

from openai import OpenAI

from app.config import Settings
from app.errors import ExternalServiceError

DEFAULT_TEST_MESSAGE = "这是一次连接测试，请用简体中文简短回复“AI连接正常”。"


def _build_client(settings: Settings) -> OpenAI:
    return OpenAI(
        api_key=settings.qwen_api_key,
        base_url=settings.qwen_base_url,
        timeout=settings.ai_timeout_seconds,
    )


def get_ai_config_status(settings: Settings) -> Dict[str, Any]:
    if not settings.qwen_api_key:
        return {
            "status": "not_configured",
            "connected": None,
            "model": settings.qwen_model,
            "base_url": settings.qwen_base_url,
            "message": "AI 未配置 API Key，当前将使用本地规则摘要。",
        }

    return {
        "status": "configured",
        "connected": None,
        "model": settings.qwen_model,
        "base_url": settings.qwen_base_url,
        "message": "AI 已配置，可点击测试按钮验证连通性。",
    }


def send_test_message(settings: Settings, message: Optional[str] = None) -> Dict[str, Any]:
    if not settings.qwen_api_key:
        raise ExternalServiceError("未配置 QWEN_API_KEY，无法测试 AI 连接。")

    prompt = (message or DEFAULT_TEST_MESSAGE).strip() or DEFAULT_TEST_MESSAGE
    client = _build_client(settings)

    try:
        completion = client.chat.completions.create(
            model=settings.qwen_model,
            messages=[
                {"role": "system", "content": "你是连接测试助手，请始终使用简体中文简短回复。"},
                {"role": "user", "content": prompt},
            ],
            temperature=0,
        )
    except Exception as exc:
        raise ExternalServiceError(f"AI 连接测试失败：{type(exc).__name__}") from exc

    response_text = (completion.choices[0].message.content or "").strip() or "AI 未返回内容。"
    return {
        "status": "connected",
        "connected": True,
        "model": settings.qwen_model,
        "base_url": settings.qwen_base_url,
        "request_message": prompt,
        "response_message": response_text,
        "message": "AI 连接测试成功。",
    }


def _compact_logs(logs: List[Dict[str, Any]], limit: int = 60) -> List[Dict[str, Any]]:
    compacted: List[Dict[str, Any]] = []
    for item in logs[:limit]:
        compacted.append(
            {
                "timestamp": item.get("timestamp"),
                "event_action": item.get("event_action"),
                "source_ip": item.get("source_ip"),
                "source_port": item.get("source_port"),
                "destination_ip": item.get("destination_ip"),
                "destination_port": item.get("destination_port"),
                "message": item.get("message"),
            }
        )
    return compacted


def _fallback_log_summary(
    logs: List[Dict[str, Any]],
    *,
    analysis_label: str,
    truncated: bool,
) -> str:
    if not logs:
        return f"{analysis_label}未找到可用于分析的日志。"

    action_counter = Counter((item.get("event_action") or "unknown") for item in logs)
    source_counter = Counter((item.get("source_ip") or "unknown") for item in logs)
    time_values = sorted(str(item.get("timestamp") or "") for item in logs if item.get("timestamp"))
    top_actions = "，".join(f"{name} {count} 条" for name, count in action_counter.most_common(3))
    top_sources = "，".join(f"{name} {count} 条" for name, count in source_counter.most_common(3))
    time_span = (
        f"时间范围 {time_values[-1]} 到 {time_values[0]}。"
        if time_values
        else "日志缺少有效时间信息。"
    )
    truncated_suffix = " 日志数量已达到分析上限。" if truncated else ""
    return (
        f"{analysis_label}共收到 {len(logs)} 条日志。{time_span}"
        f" 主要动作：{top_actions or '无'}。"
        f" 主要来源：{top_sources or '无'}。"
        f"{truncated_suffix}"
    ).strip()


def summarize_logs_with_qwen(
    settings: Settings,
    logs: List[Dict[str, Any]],
    *,
    analysis_label: str,
    truncated: bool = False,
) -> str:
    fallback_summary = _fallback_log_summary(
        logs,
        analysis_label=analysis_label,
        truncated=truncated,
    )
    if not logs:
        return fallback_summary

    if not settings.qwen_api_key:
        return f"{fallback_summary} 当前未配置 AI，已返回本地摘要。"

    client = _build_client(settings)
    prompt = {
        "analysis_label": analysis_label,
        "total_logs": len(logs),
        "logs_truncated": truncated,
        "logs": _compact_logs(logs),
        "task": "请你作为安全分析师，根据这些原始日志输出3到5条简短结论，并给出处置建议；如果整体看起来正常，也请明确说明。",
    }
    try:
        completion = client.chat.completions.create(
            model=settings.qwen_model,
            messages=[
                {"role": "system", "content": "你是企业安全日志分析助手，请用简体中文回答。"},
                {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
            ],
            temperature=0.2,
        )
    except Exception:
        return f"{fallback_summary} AI 总结生成失败，已返回本地摘要。"

    return (completion.choices[0].message.content or "").strip() or "AI 未返回内容。"


def summarize_with_qwen(
    settings: Settings, alerts: List[Dict[str, Any]], total_logs: int, minutes: int
) -> str:
    if not alerts:
        return f"最近 {minutes} 分钟未发现可疑事件（共检查 {total_logs} 条日志）。"

    fallback_summary = (
        f"最近 {minutes} 分钟检测到 {len(alerts)} 条可疑事件（共检查 {total_logs} 条日志）。"
        "建议优先检查被阻断流量、高危端口访问和高频来源 IP。"
    )

    if not settings.qwen_api_key:
        return fallback_summary

    client = _build_client(settings)
    prompt = {
        "window_minutes": minutes,
        "total_logs": total_logs,
        "alerts": alerts[:60],
        "task": "请你作为安全分析师，输出3到5条简短结论，并给出处置建议。",
    }

    try:
        completion = client.chat.completions.create(
            model=settings.qwen_model,
            messages=[
                {"role": "system", "content": "你是企业安全日志分析助手，请用简体中文回答。"},
                {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
            ],
            temperature=0.2,
        )
    except Exception:
        return f"{fallback_summary} AI 总结生成失败，已返回本地规则摘要。"

    return completion.choices[0].message.content or "AI 未返回内容。"
