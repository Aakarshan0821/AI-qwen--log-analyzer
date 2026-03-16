from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class LogEvent(BaseModel):
    id: Optional[str] = None
    index: Optional[str] = None
    timestamp: Optional[str] = None
    event_action: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    message: str = ""
    raw: Dict[str, Any] = Field(default_factory=dict)


class SearchResult(BaseModel):
    total: int
    page: int
    size: int
    total_pages: int
    has_prev: bool
    has_next: bool
    logs: List[LogEvent]


class SelectedLogAnalysisRequest(BaseModel):
    selected_logs: List[LogEvent] = Field(min_items=1, max_items=500)


class TimeRangeAnalysisRequest(BaseModel):
    start: str
    end: str
    size: int = Field(default=200, ge=1, le=10000)
    source_ip: Optional[str] = None
    source_ip_mode: Literal["exact", "prefix"] = "exact"
    destination_ip: Optional[str] = None
    destination_ip_mode: Literal["exact", "prefix"] = "exact"
    exclude_source_ip_prefixes: List[str] = Field(default_factory=list, max_length=20)


class AutoAnalysisSettingsRequest(BaseModel):
    enabled: bool = True
    interval_minutes: int = Field(default=10, ge=1, le=1440)
    exclude_source_ip_prefixes: List[str] = Field(default_factory=list, max_length=20)
    exclude_destination_ip_prefixes: List[str] = Field(default_factory=list, max_length=20)
    exclude_event_actions: List[str] = Field(default_factory=list, max_length=20)
    exclude_message_keywords: List[str] = Field(default_factory=list, max_length=20)


class DeleteLogsRequest(BaseModel):
    before: str
    ip: Optional[str] = None
    ip_mode: Literal["exact", "prefix"] = "exact"
