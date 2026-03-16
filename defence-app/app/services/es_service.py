import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from elasticsearch import Elasticsearch

from app.config import Settings
from app.errors import ExternalServiceError, ValidationError
from app.schemas import SearchResult

logger = logging.getLogger(__name__)
PIT_KEEP_ALIVE = "1m"


def get_es_client(settings: Settings) -> Elasticsearch:
    kwargs: Dict[str, Any] = {"request_timeout": settings.es_timeout_seconds}
    if settings.es_username and settings.es_password:
        kwargs["basic_auth"] = (settings.es_username, settings.es_password)
    return Elasticsearch(settings.es_url, **kwargs)


def parse_iso(value: Optional[str]) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except ValueError as exc:
        raise ValidationError("时间格式无效，请使用 ISO8601 格式。") from exc


def _value(doc: Dict[str, Any], *keys: str) -> Optional[Any]:
    current: Any = doc
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def _normalize_port(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _string_value(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


def _parse_ip_value(value: Any) -> Any:
    if value in (None, ""):
        return None
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


def _pick_preferred_ip(*candidates: Any) -> Optional[str]:
    normalized_candidates: List[str] = []
    for item in candidates:
        if isinstance(item, list):
            for sub_item in item:
                normalized = _string_value(sub_item)
                if normalized:
                    normalized_candidates.append(normalized)
            continue
        normalized = _string_value(item)
        if normalized:
            normalized_candidates.append(normalized)
    for candidate in normalized_candidates:
        if _parse_ip_value(candidate):
            return candidate
    return normalized_candidates[0] if normalized_candidates else None


def _pick_first_non_empty(*candidates: Any) -> Optional[str]:
    for candidate in candidates:
        if isinstance(candidate, list):
            for item in candidate:
                normalized = _string_value(item)
                if normalized:
                    return normalized
            continue
        normalized = _string_value(candidate)
        if normalized:
            return normalized
    return None


def _pick_port(*candidates: Any) -> int | None:
    for candidate in candidates:
        if isinstance(candidate, list):
            for item in candidate:
                normalized = _normalize_port(item)
                if normalized is not None:
                    return normalized
            continue
        normalized = _normalize_port(candidate)
        if normalized is not None:
            return normalized
    return None


def _pfsense_ip_port_fields(src: Dict[str, Any]) -> Dict[str, Optional[Any]]:
    pfsense = src.get("pfsense", {}) if isinstance(src.get("pfsense"), dict) else {}
    ip_version = str(pfsense.get("ip_version") or "").strip()
    if ip_version == "4":
        return {
            "source_ip": pfsense.get("column19"),
            "destination_ip": pfsense.get("column20"),
            "source_port": pfsense.get("column21"),
            "destination_port": pfsense.get("column22"),
        }
    if ip_version == "6":
        return {
            "source_ip": pfsense.get("column16"),
            "destination_ip": pfsense.get("column17"),
            "source_port": pfsense.get("column18"),
            "destination_port": pfsense.get("column19"),
        }
    return {
        "source_ip": pfsense.get("column19") or pfsense.get("column16"),
        "destination_ip": pfsense.get("column20") or pfsense.get("column17"),
        "source_port": pfsense.get("column21") or pfsense.get("column18"),
        "destination_port": pfsense.get("column22") or pfsense.get("column19"),
    }


def _opnsense_ip_port_fields(src: Dict[str, Any]) -> Dict[str, Optional[Any]]:
    opnsense = src.get("opnsense", {}) if isinstance(src.get("opnsense"), dict) else {}
    ip_version = str(opnsense.get("ip_version") or "").strip()
    if ip_version == "4":
        return {
            "source_ip": opnsense.get("column19"),
            "destination_ip": opnsense.get("column20"),
            "source_port": opnsense.get("column21"),
            "destination_port": opnsense.get("column22"),
        }
    if ip_version == "6":
        return {
            "source_ip": opnsense.get("column16"),
            "destination_ip": opnsense.get("column17"),
            "source_port": opnsense.get("column18"),
            "destination_port": opnsense.get("column19"),
        }
    return {
        "source_ip": opnsense.get("column19") or opnsense.get("column16"),
        "destination_ip": opnsense.get("column20") or opnsense.get("column17"),
        "source_port": opnsense.get("column21") or opnsense.get("column18"),
        "destination_port": opnsense.get("column22") or opnsense.get("column19"),
    }


def _pick_event_action(src: Dict[str, Any]) -> Optional[str]:
    return _pick_first_non_empty(
        _value(src, "event", "action"),
        _value(src, "rule", "action"),
        _value(src, "waf", "action"),
        _value(src, "firewall", "action"),
        _value(src, "modsecurity", "action"),
        _value(src, "nginx", "app_protect", "outcome"),
        _value(src, "pfsense", "action"),
        _value(src, "opnsense", "action"),
        src.get("action"),
        _value(src, "event", "outcome"),
    )


def _pick_message(src: Dict[str, Any]) -> str:
    return (
        _pick_first_non_empty(
            src.get("message"),
            _value(src, "event", "original"),
            _value(src, "log", "original"),
            _value(src, "modsecurity", "message"),
            _value(src, "waf", "message"),
            _value(src, "rule", "name"),
        )
        or ""
    )


def extract_event(hit: Dict[str, Any]) -> Dict[str, Any]:
    src = hit.get("_source", {})
    pfsense_fields = _pfsense_ip_port_fields(src)
    opnsense_fields = _opnsense_ip_port_fields(src)
    event_action = _pick_event_action(src)
    source_ip = _pick_preferred_ip(
        _value(src, "source", "ip"),
        _value(src, "client", "ip"),
        _value(src, "source", "address"),
        _value(src, "client", "address"),
        src.get("src_ip"),
        src.get("remote_addr"),
        pfsense_fields["source_ip"],
        opnsense_fields["source_ip"],
    )
    destination_ip = _pick_preferred_ip(
        _value(src, "destination", "ip"),
        _value(src, "server", "ip"),
        _value(src, "destination", "address"),
        _value(src, "server", "address"),
        src.get("dst_ip"),
        pfsense_fields["destination_ip"],
        opnsense_fields["destination_ip"],
        _value(src, "host", "ip"),
    )
    destination_port = _pick_port(
        _value(src, "destination", "port"),
        _value(src, "server", "port"),
        _value(src, "url", "port"),
        src.get("dst_port"),
        pfsense_fields["destination_port"],
        opnsense_fields["destination_port"],
    )
    source_port = _pick_port(
        _value(src, "source", "port"),
        _value(src, "client", "port"),
        src.get("src_port"),
        pfsense_fields["source_port"],
        opnsense_fields["source_port"],
    )
    return {
        "id": hit.get("_id"),
        "index": hit.get("_index"),
        "timestamp": src.get("@timestamp"),
        "event_action": event_action,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "message": _pick_message(src),
        "raw": src,
    }


SOURCE_IP_EXACT_FIELDS = [
    "source.ip",
    "client.ip",
    "source.address",
    "client.address",
    "src_ip",
    "remote_addr",
    "pfsense.column16",
    "pfsense.column19",
    "opnsense.column16",
    "opnsense.column19",
]

DESTINATION_IP_EXACT_FIELDS = [
    "destination.ip",
    "server.ip",
    "host.ip",
    "destination.address",
    "server.address",
    "dst_ip",
    "pfsense.column17",
    "pfsense.column20",
    "opnsense.column17",
    "opnsense.column20",
]

SOURCE_IP_PREFIX_FIELDS = [
    "source.address",
    "client.address",
    "src_ip",
    "remote_addr",
    "pfsense.column16",
    "pfsense.column19",
    "opnsense.column16",
    "opnsense.column19",
]

DESTINATION_IP_PREFIX_FIELDS = [
    "destination.address",
    "server.address",
    "dst_ip",
    "pfsense.column17",
    "pfsense.column20",
    "opnsense.column17",
    "opnsense.column20",
]

SOURCE_IP_RANGE_FIELDS = ["source.ip", "client.ip"]
DESTINATION_IP_RANGE_FIELDS = ["destination.ip", "server.ip", "host.ip"]


def _term_clauses(fields: List[str], value: str) -> List[Dict[str, Any]]:
    clauses: List[Dict[str, Any]] = []
    for field in fields:
        clauses.append({"term": {field: value}})
        if not field.endswith(".keyword") and "." in field and not field.endswith(".ip") and not field.endswith(".port"):
            clauses.append({"term": {f"{field}.keyword": value}})
    return clauses


def _prefix_clauses(fields: List[str], value: str) -> List[Dict[str, Any]]:
    clauses: List[Dict[str, Any]] = []
    for field in fields:
        clauses.append({"prefix": {field: value}})
        if not field.endswith(".keyword") and "." in field and not field.endswith(".ip") and not field.endswith(".port"):
            clauses.append({"prefix": {f"{field}.keyword": value}})
    return clauses


def _range_clauses(fields: List[str], range_start: str, range_end: str) -> List[Dict[str, Any]]:
    return [{"range": {field: {"gte": range_start, "lte": range_end}}} for field in fields]


def _normalize_ip_mode(ip_mode: str) -> str:
    if ip_mode not in {"exact", "prefix"}:
        raise ValidationError("IP 匹配方式无效。")
    return ip_mode


def _build_exact_source_ip_clause(ip: str) -> Dict[str, Any]:
    return {
        "bool": {
            "should": _term_clauses(SOURCE_IP_EXACT_FIELDS, ip),
            "minimum_should_match": 1,
        }
    }


def _build_exact_destination_ip_clause(ip: str) -> Dict[str, Any]:
    return {
        "bool": {
            "should": _term_clauses(DESTINATION_IP_EXACT_FIELDS, ip),
            "minimum_should_match": 1,
        }
    }


def _ipv4_prefix_range(ip_prefix: str) -> Tuple[str, str] | None:
    cleaned = ip_prefix.strip().rstrip(".")
    if not cleaned:
        raise ValidationError("IP 前缀不能为空。")

    parts = cleaned.split(".")
    if not 1 <= len(parts) <= 4 or any(not part.isdigit() for part in parts):
        raise ValidationError("IP 前缀格式无效，请输入如 192.168 或 10.0.0。")

    octets = [int(part) for part in parts]
    if any(part < 0 or part > 255 for part in octets):
        raise ValidationError("IP 前缀格式无效，请输入有效的 IPv4 段。")

    padded = octets + [0] * (4 - len(octets))
    prefix_length = len(octets) * 8
    network = ipaddress.ip_network((".".join(str(part) for part in padded), prefix_length), strict=False)
    return str(network.network_address), str(network.broadcast_address)


def _build_prefix_source_ip_clause(ip_prefix: str) -> Dict[str, Any]:
    normalized_prefix = ip_prefix.strip().rstrip(".")
    range_start, range_end = _ipv4_prefix_range(normalized_prefix)
    return {
        "bool": {
            "should": _range_clauses(SOURCE_IP_RANGE_FIELDS, range_start, range_end)
            + _prefix_clauses(SOURCE_IP_PREFIX_FIELDS, normalized_prefix),
            "minimum_should_match": 1,
        }
    }


def _build_prefix_destination_ip_clause(ip_prefix: str) -> Dict[str, Any]:
    normalized_prefix = ip_prefix.strip().rstrip(".")
    range_start, range_end = _ipv4_prefix_range(normalized_prefix)
    return {
        "bool": {
            "should": _range_clauses(DESTINATION_IP_RANGE_FIELDS, range_start, range_end)
            + _prefix_clauses(DESTINATION_IP_PREFIX_FIELDS, normalized_prefix),
            "minimum_should_match": 1,
        }
    }


def _build_ip_clause(ip: str, ip_mode: str, direction: str) -> Dict[str, Any]:
    normalized_ip = ip.strip()
    if not normalized_ip:
        raise ValidationError("IP 地址不能为空。")

    normalized_mode = _normalize_ip_mode(ip_mode)
    if direction not in {"source", "destination"}:
        raise ValidationError("IP 方向无效。")

    if direction == "source":
        if normalized_mode == "prefix":
            return _build_prefix_source_ip_clause(normalized_ip)
        return _build_exact_source_ip_clause(normalized_ip)

    if normalized_mode == "prefix":
        return _build_prefix_destination_ip_clause(normalized_ip)
    return _build_exact_destination_ip_clause(normalized_ip)


def _normalize_ip_prefixes(prefixes: Optional[List[str]]) -> List[str]:
    if not prefixes:
        return []
    normalized: List[str] = []
    for item in prefixes:
        token = (item or "").strip().rstrip(".")
        if not token:
            continue
        _ipv4_prefix_range(token)
        normalized.append(token)
    return normalized


def _build_window_sort(*, use_pit: bool) -> List[Dict[str, Any]]:
    sort: List[Dict[str, Any]] = [{"@timestamp": {"order": "desc"}}]
    if use_pit:
        sort.append({"_shard_doc": {"order": "desc"}})
    return sort


def _open_point_in_time(es: Elasticsearch, settings: Settings) -> Optional[str]:
    try:
        response = es.open_point_in_time(
            index=settings.es_index_pattern,
            keep_alive=PIT_KEEP_ALIVE,
        )
    except Exception as exc:  # pragma: no cover
        logger.warning(
            "Failed to open point-in-time search context, falling back to timestamp-only pagination.",
            exc_info=exc,
        )
        return None

    pit_id = str(response.get("id") or "").strip()
    if not pit_id:
        logger.warning(
            "Point-in-time search did not return an id, falling back to timestamp-only pagination."
        )
        return None
    return pit_id


def _close_point_in_time(es: Elasticsearch, pit_id: Optional[str]) -> None:
    if not pit_id:
        return
    try:
        es.close_point_in_time(id=pit_id)
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to close point-in-time search context.", exc_info=exc)


def _build_query(
    source_ip: Optional[str],
    destination_ip: Optional[str],
    start_dt: datetime,
    end_dt: datetime,
    source_ip_mode: str = "exact",
    destination_ip_mode: str = "exact",
    exclude_source_ip_prefixes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    query: Dict[str, Any] = {
        "bool": {
            "must": [
                {
                    "range": {
                        "@timestamp": {
                            "gte": start_dt.isoformat(),
                            "lte": end_dt.isoformat(),
                        }
                    }
                }
            ]
        }
    }

    if source_ip:
        query["bool"]["must"].append(_build_ip_clause(source_ip, source_ip_mode, "source"))
    if destination_ip:
        query["bool"]["must"].append(
            _build_ip_clause(destination_ip, destination_ip_mode, "destination")
        )
    excluded = _normalize_ip_prefixes(exclude_source_ip_prefixes)
    if excluded:
        query["bool"]["must_not"] = [_build_prefix_source_ip_clause(item) for item in excluded]

    return query


def search_logs(
    settings: Settings,
    source_ip: Optional[str],
    destination_ip: Optional[str],
    start: Optional[str],
    end: Optional[str],
    size: int,
    page: int = 1,
    source_ip_mode: str = "exact",
    destination_ip_mode: str = "exact",
    exclude_source_ip_prefixes: Optional[List[str]] = None,
) -> SearchResult:
    end_dt = parse_iso(end) if end else datetime.now(timezone.utc)
    start_dt = parse_iso(start) if start else end_dt - timedelta(hours=1)
    if page < 1:
        raise ValidationError("页码必须大于等于 1。")
    if start_dt > end_dt:
        raise ValidationError("开始时间不能晚于结束时间。")

    query = _build_query(
        source_ip,
        destination_ip,
        start_dt,
        end_dt,
        source_ip_mode=source_ip_mode,
        destination_ip_mode=destination_ip_mode,
        exclude_source_ip_prefixes=exclude_source_ip_prefixes,
    )
    es = get_es_client(settings)
    try:
        request_kwargs: Dict[str, Any] = {
            "index": settings.es_index_pattern,
            "query": query,
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        if page > 1:
            request_kwargs["from_"] = (page - 1) * size
        result = es.search(**request_kwargs)
    except Exception as exc:  # pragma: no cover
        raise ExternalServiceError("查询 Elasticsearch 失败，请检查连接和索引配置。") from exc

    hits = result.get("hits", {}).get("hits", [])
    total_raw = result.get("hits", {}).get("total", 0)
    total = total_raw.get("value", 0) if isinstance(total_raw, dict) else int(total_raw or 0)
    total_pages = (total + size - 1) // size if total else 0
    return SearchResult(
        total=total,
        page=page,
        size=size,
        total_pages=total_pages,
        has_prev=page > 1 and total_pages > 0,
        has_next=total_pages > 0 and page < total_pages,
        logs=[extract_event(item) for item in hits],
    )


def _fetch_events_between(
    settings: Settings,
    *,
    start_dt: datetime,
    end_dt: datetime,
    limit: int,
    source_ip: Optional[str] = None,
    source_ip_mode: str = "exact",
    destination_ip: Optional[str] = None,
    destination_ip_mode: str = "exact",
    exclude_source_ip_prefixes: Optional[List[str]] = None,
) -> Tuple[List[Dict[str, Any]], bool]:
    if start_dt > end_dt:
        raise ValidationError("开始时间不能晚于结束时间。")

    es = get_es_client(settings)
    pit_id = _open_point_in_time(es, settings)
    sort = _build_window_sort(use_pit=bool(pit_id))
    search_after: List[Any] | None = None
    events: List[Dict[str, Any]] = []
    truncated = False
    query = _build_query(
        source_ip,
        destination_ip,
        start_dt,
        end_dt,
        source_ip_mode=source_ip_mode,
        destination_ip_mode=destination_ip_mode,
        exclude_source_ip_prefixes=exclude_source_ip_prefixes,
    )

    try:
        while len(events) < limit:
            page_size = min(settings.es_search_batch_size, limit - len(events))
            if page_size <= 0:
                break
            request_kwargs: Dict[str, Any] = {
                "query": query,
                "size": page_size,
                "sort": sort,
            }
            if pit_id:
                request_kwargs["pit"] = {"id": pit_id, "keep_alive": PIT_KEEP_ALIVE}
            else:
                request_kwargs["index"] = settings.es_index_pattern
            if search_after:
                request_kwargs["search_after"] = search_after

            result = es.search(**request_kwargs)
            hits = result.get("hits", {}).get("hits", [])
            if not hits:
                break

            events.extend(extract_event(item) for item in hits)
            if len(events) >= limit:
                truncated = True
                break

            if len(hits) < page_size:
                break

            search_after = hits[-1].get("sort")
            if not search_after:
                break
    except ValidationError:
        raise
    except Exception as exc:  # pragma: no cover
        raise ExternalServiceError("拉取检测窗口日志失败，请检查 Elasticsearch 配置。") from exc
    finally:
        _close_point_in_time(es, pit_id)

    return events, truncated


def delete_logs_before(
    settings: Settings,
    *,
    before: str,
    ip: Optional[str] = None,
    ip_mode: str = "exact",
) -> Dict[str, Any]:
    before_dt = parse_iso(before)
    query: Dict[str, Any] = {
        "bool": {
            "must": [
                {
                    "range": {
                        "@timestamp": {
                            "lt": before_dt.isoformat(),
                        }
                    }
                }
            ]
        }
    }
    if ip:
        query["bool"]["must"].append(_build_ip_clause(ip, ip_mode, "source"))

    es = get_es_client(settings)
    try:
        result = es.delete_by_query(
            index=settings.es_index_pattern,
            query=query,
            conflicts="proceed",
            refresh=True,
            wait_for_completion=True,
        )
    except ValidationError:
        raise
    except Exception as exc:  # pragma: no cover
        raise ExternalServiceError("删除日志失败，请检查 Elasticsearch 连接、权限和索引配置。") from exc

    failures = result.get("failures") or []
    if failures:
        raise ExternalServiceError("删除日志时部分分片执行失败，请检查 Elasticsearch 日志。")

    return {
        "before": before_dt.isoformat(),
        "matched": int(result.get("total", 0)),
        "deleted": int(result.get("deleted", 0)),
        "batches": int(result.get("batches", 0)),
        "version_conflicts": int(result.get("version_conflicts", 0)),
        "ip": ip.strip() if ip else None,
        "ip_mode": _normalize_ip_mode(ip_mode) if ip else None,
    }


def fetch_window_events(
    settings: Settings,
    *,
    minutes: int,
    exclude_source_ip_prefixes: Optional[List[str]] = None,
) -> Tuple[List[Dict[str, Any]], bool]:
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(minutes=minutes)
    return _fetch_events_between(
        settings,
        start_dt=start_dt,
        end_dt=end_dt,
        limit=settings.detection_max_logs,
        exclude_source_ip_prefixes=exclude_source_ip_prefixes,
    )

def fetch_range_events(
    settings: Settings,
    *,
    start: str,
    end: str,
    size: int | None = None,
    source_ip: Optional[str] = None,
    source_ip_mode: str = "exact",
    destination_ip: Optional[str] = None,
    destination_ip_mode: str = "exact",
    exclude_source_ip_prefixes: Optional[List[str]] = None,
) -> Tuple[List[Dict[str, Any]], bool]:
    start_dt = parse_iso(start)
    end_dt = parse_iso(end)
    limit = min(size or settings.detection_max_logs, settings.detection_max_logs)
    return _fetch_events_between(
        settings,
        start_dt=start_dt,
        end_dt=end_dt,
        limit=limit,
        source_ip=source_ip,
        source_ip_mode=source_ip_mode,
        destination_ip=destination_ip,
        destination_ip_mode=destination_ip_mode,
        exclude_source_ip_prefixes=exclude_source_ip_prefixes,
    )


def check_es_health(settings: Settings) -> Dict[str, Any]:
    try:
        healthy = bool(get_es_client(settings).ping())
    except Exception:
        healthy = False
    return {
        "status": "up" if healthy else "down",
        "url": settings.es_url,
        "index_pattern": settings.es_index_pattern,
    }
