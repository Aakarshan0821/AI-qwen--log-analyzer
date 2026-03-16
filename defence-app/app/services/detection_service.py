from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from app.config import Settings
from app.services.ai_service import summarize_with_qwen
from app.services.es_service import fetch_window_events

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}
RULE_LABELS = {
    "blocked_traffic": "阻断流量",
    "risky_destination_port": "高危目标端口",
    "high_frequency_source_ip": "高频来源 IP",
}


def _severity_for_event(action: str, destination_port: int | None, settings: Settings) -> str | None:
    if destination_port in settings.risky_ports:
        return "high"
    if action == "block":
        return "medium"
    return None


def _merge_reasons(existing: List[str], new_reason: str) -> List[str]:
    if new_reason in existing:
        return existing
    return existing + [new_reason]


def _reason_labels(reasons: List[str]) -> List[str]:
    return [RULE_LABELS.get(reason, reason) for reason in reasons]


def _build_event_alert_key(event: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        event.get("timestamp"),
        event.get("source_ip"),
        event.get("destination_ip"),
        event.get("destination_port"),
        event.get("event_action"),
        event.get("message"),
    )


def _sort_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        alerts,
        key=lambda item: (
            SEVERITY_ORDER.get(item.get("severity", "low"), 0),
            item.get("timestamp") or "",
        ),
        reverse=True,
    )


def _matches_prefixes(value: str | None, prefixes: List[str]) -> bool:
    normalized_value = str(value or "").strip()
    if not normalized_value:
        return False
    return any(normalized_value.startswith(prefix) for prefix in prefixes)


def _filter_events(
    events: List[Dict[str, Any]],
    *,
    exclude_destination_ip_prefixes: List[str] | None = None,
    exclude_event_actions: List[str] | None = None,
    exclude_message_keywords: List[str] | None = None,
) -> Tuple[List[Dict[str, Any]], int]:
    destination_prefixes = [item.strip() for item in exclude_destination_ip_prefixes or [] if item.strip()]
    action_filters = {item.strip().lower() for item in exclude_event_actions or [] if item.strip()}
    message_keywords = [item.strip().lower() for item in exclude_message_keywords or [] if item.strip()]

    filtered_events: List[Dict[str, Any]] = []
    excluded_count = 0

    for event in events:
        action = str(event.get("event_action") or "").strip().lower()
        message = str(event.get("message") or "").lower()
        destination_ip = event.get("destination_ip")

        if action_filters and action in action_filters:
            excluded_count += 1
            continue
        if destination_prefixes and _matches_prefixes(destination_ip, destination_prefixes):
            excluded_count += 1
            continue
        if message_keywords and any(keyword in message for keyword in message_keywords):
            excluded_count += 1
            continue

        filtered_events.append(event)

    return filtered_events, excluded_count


def build_detection_report(
    settings: Settings,
    minutes: int,
    *,
    exclude_source_ip_prefixes: List[str] | None = None,
    exclude_destination_ip_prefixes: List[str] | None = None,
    exclude_event_actions: List[str] | None = None,
    exclude_message_keywords: List[str] | None = None,
) -> Dict[str, Any]:
    events, truncated = fetch_window_events(
        settings,
        minutes=minutes,
        exclude_source_ip_prefixes=exclude_source_ip_prefixes,
    )
    events, excluded_count = _filter_events(
        events,
        exclude_destination_ip_prefixes=exclude_destination_ip_prefixes,
        exclude_event_actions=exclude_event_actions,
        exclude_message_keywords=exclude_message_keywords,
    )
    src_counter = Counter((event.get("source_ip") or "unknown") for event in events)
    event_alerts: Dict[Tuple[Any, ...], Dict[str, Any]] = {}

    for event in events:
        src_ip = event.get("source_ip") or "unknown"
        action = (event.get("event_action") or "").lower()
        destination_port = event.get("destination_port")

        matched_reasons: List[str] = []
        if action == "block":
            matched_reasons.append("blocked_traffic")
        if destination_port in settings.risky_ports:
            matched_reasons.append("risky_destination_port")

        if not matched_reasons:
            continue

        alert_key = _build_event_alert_key(event)
        current_alert = event_alerts.get(alert_key)
        severity = _severity_for_event(action, destination_port, settings) or "low"
        if current_alert is None:
            event_alerts[alert_key] = {
                "type": "event",
                "severity": severity,
                "reasons": matched_reasons,
                "reason_labels": _reason_labels(matched_reasons),
                "source_ip": src_ip,
                "source_port": event.get("source_port"),
                "destination_ip": event.get("destination_ip"),
                "destination_port": destination_port,
                "timestamp": event.get("timestamp"),
                "event_action": event.get("event_action"),
                "message": event.get("message"),
                "raw": event.get("raw") or {},
            }
            continue

        for reason in matched_reasons:
            current_alert["reasons"] = _merge_reasons(current_alert["reasons"], reason)
        current_alert["reason_labels"] = _reason_labels(current_alert["reasons"])
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(
            current_alert.get("severity", "low"), 0
        ):
            current_alert["severity"] = severity

    alerts = list(event_alerts.values())

    for src_ip, count in src_counter.items():
        if src_ip == "unknown" or count < settings.suspicious_threshold:
            continue

        sample_events = [
            event
            for event in events
            if (event.get("source_ip") or "unknown") == src_ip
        ][:5]
        destinations = sorted(
            {
                str(event.get("destination_port"))
                for event in sample_events
                if event.get("destination_port") is not None
            }
        )
        alerts.append(
            {
                "type": "aggregate",
                "severity": "high",
                "reasons": ["high_frequency_source_ip"],
                "reason_labels": _reason_labels(["high_frequency_source_ip"]),
                "source_ip": src_ip,
                "destination_ip": None,
                "destination_port": None,
                "timestamp": sample_events[0].get("timestamp") if sample_events else None,
                "event_action": None,
                "event_count": count,
                "window_minutes": minutes,
                "sample_destination_ports": destinations,
                "message": f"{src_ip} 在 {minutes} 分钟内出现 {count} 次。",
            }
        )

    sorted_alerts = _sort_alerts(alerts)
    displayed_alerts = sorted_alerts[: settings.max_alerts_display]
    ai_summary = summarize_with_qwen(settings, displayed_alerts, len(events), minutes)

    return {
        "status": "ok",
        "window_minutes": minutes,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "total_logs": len(events),
        "excluded_logs": excluded_count,
        "logs_truncated": truncated,
        "suspicious_count": len(sorted_alerts),
        "returned_alerts": len(displayed_alerts),
        "alerts": displayed_alerts,
        "ai_summary": ai_summary,
        "message": (
            f"检测完成，已按自动分析规则排除 {excluded_count} 条日志。"
            if excluded_count
            else "检测完成。"
        ),
    }
