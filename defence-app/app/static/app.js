const appRoot = document.querySelector(".container");
const autoRefreshSeconds = Number(appRoot.dataset.autoRefreshSeconds || 60);
let latestRefreshInFlight = false;
let currentSearchLogs = [];
let currentSearchMeta = { total: 0, shown: 0, page: 0, size: 0, totalPages: 0, hasPrev: false, hasNext: false };
let currentSearchRequest = null;
const selectedLogs = new Map();
let autoAnalysisSettings = null;

function queryById(id) {
  return document.getElementById(id);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function toIso(localDateTime) {
  if (!localDateTime) return null;
  return new Date(localDateTime).toISOString();
}

function formatDateTime(value) {
  if (!value) return "未知时间";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("zh-CN", { hour12: false });
}

function formatForInput(date) {
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours()
  )}:${pad(date.getMinutes())}`;
}

function splitCsv(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function statusClass(type) {
  if (type === "success") return "status-success";
  if (type === "error") return "status-error";
  if (type === "warning") return "status-warning";
  return "status-neutral";
}

function statusIcon(type) {
  if (type === "success") {
    return `
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12.75 11.25 15 15 9.75m6 2.25a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
      </svg>
    `;
  }
  if (type === "error") {
    return `
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v3.75m9-.75a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 6h.008v.008H12V18Z" />
      </svg>
    `;
  }
  if (type === "warning") {
    return `
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2.25m0 3.75h.008v.008H12V15Zm-8.02 3.615h16.04c1.432 0 2.33-1.55 1.614-2.793L13.614 4.95c-.716-1.243-2.512-1.243-3.228 0L2.366 15.822c-.716 1.243.182 2.793 1.614 2.793Z" />
      </svg>
    `;
  }
  return `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11.25 11.25 12 11.25v5.25H12.75m-.75-9h.008v.008H12V7.5Z" />
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
    </svg>
  `;
}

function setStatus(elementId, message, type = "neutral") {
  const element = queryById(elementId);
  element.className = `status-banner ${statusClass(type)}`;
  element.innerHTML = `${statusIcon(type)}<span>${escapeHtml(message)}</span>`;
}

function setButtonLoading(buttonId, loading, loadingText) {
  const button = queryById(buttonId);
  if (!button.dataset.defaultText) {
    button.dataset.defaultText = button.textContent;
  }
  button.disabled = loading;
  button.textContent = loading ? loadingText : button.dataset.defaultText;
}

function renderChips(elementId, items) {
  const element = queryById(elementId);
  if (!items.length) {
    element.innerHTML = "";
    return;
  }
  element.innerHTML = items.map((item) => `<span class="chip">${escapeHtml(item)}</span>`).join("");
}

function renderEmptyState(elementId, message) {
  queryById(elementId).innerHTML = `<div class="empty-state">${escapeHtml(message)}</div>`;
}

function renderSummaryText(elementId, message) {
  const element = queryById(elementId);
  element.textContent = message;
  element.classList.toggle("empty-state", !message);
}

function normalizeLog(log) {
  return {
    id: log.id ?? null,
    index: log.index ?? null,
    timestamp: log.timestamp ?? null,
    event_action: log.event_action ?? null,
    source_ip: log.source_ip ?? null,
    source_port: log.source_port ?? null,
    destination_ip: log.destination_ip ?? null,
    destination_port: log.destination_port ?? null,
    message: log.message || "",
    raw: log.raw || {},
  };
}

function formatRawLog(raw) {
  if (!raw || typeof raw !== "object" || !Object.keys(raw).length) {
    return "无完整原始日志。";
  }
  return JSON.stringify(raw, null, 2);
}

function serializeLogForApi(log) {
  return {
    id: log.id,
    index: log.index,
    timestamp: log.timestamp,
    event_action: log.event_action,
    source_ip: log.source_ip,
    source_port: log.source_port,
    destination_ip: log.destination_ip,
    destination_port: log.destination_port,
    message: log.message,
    raw: log.raw,
  };
}

function getLogKey(log) {
  if (log.id) return `${log.index || "unknown-index"}:${log.id}`;
  return [
    log.timestamp || "",
    log.source_ip || "",
    log.destination_ip || "",
    log.destination_port ?? "",
    log.event_action || "",
    log.message || "",
  ].join("|");
}

function setActiveView(viewId) {
  document.querySelectorAll(".view-panel").forEach((panel) => {
    panel.classList.toggle("is-hidden", panel.id !== viewId);
  });
  document.querySelectorAll(".menu-btn").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.view === viewId);
  });
}

function renderSelectedState() {
  const count = selectedLogs.size;
  const pageLabel =
    currentSearchMeta.totalPages > 0 ? `第 ${currentSearchMeta.page}/${currentSearchMeta.totalPages} 页` : "未分页";
  renderSummaryText(
    "selectedCountText",
    count ? `当前已勾选 ${count} 条日志，可直接到 AI分析 生成总结。` : "当前未勾选任何日志。"
  );
  renderChips("selectedAnalysisMeta", count ? [`已选日志 ${count} 条`] : []);
  renderChips("searchMeta", [
    `命中总数 ${currentSearchMeta.total}`,
    `当前展示 ${currentSearchMeta.shown}`,
    pageLabel,
    `已选日志 ${count}`,
  ]);
}

function bindSearchLogSelection() {
  document.querySelectorAll(".search-log-checkbox").forEach((checkbox) => {
    checkbox.addEventListener("change", (event) => {
      const key = event.target.dataset.logKey;
      const log = currentSearchLogs.find((item) => getLogKey(item) === key);
      if (!log) return;
      if (event.target.checked) {
        selectedLogs.set(key, log);
      } else {
        selectedLogs.delete(key);
      }
      renderSelectedState();
      renderSearchResults({
        total: currentSearchMeta.total,
        page: currentSearchMeta.page,
        size: currentSearchMeta.size,
        total_pages: currentSearchMeta.totalPages,
        has_prev: currentSearchMeta.hasPrev,
        has_next: currentSearchMeta.hasNext,
        logs: currentSearchLogs,
      });
    });
  });
}

function renderRawDetails(raw, label = "查看完整日志") {
  return `
    <details class="log-details">
      <summary>${escapeHtml(label)}</summary>
      <pre class="raw-log">${escapeHtml(formatRawLog(raw))}</pre>
    </details>
  `;
}

function renderLogCard(log, { selectable = false } = {}) {
  const source = log.source_ip || "-";
  const destination = log.destination_ip || "-";
  const port = log.destination_port ?? "-";
  const action = log.event_action || "unknown";
  const logKey = getLogKey(log);
  const selected = selectedLogs.has(logKey);
  return `
    <article class="event-card card log-card ${selected ? "is-selected" : ""}">
      <div class="card-body">
      ${
        selectable
          ? `<label class="event-select">
              <input
                class="search-log-checkbox"
                type="checkbox"
                data-log-key="${escapeHtml(logKey)}"
                ${selected ? "checked" : ""}
              />
              <span>${selected ? "已选中，可用于 AI 分析" : "勾选后可加入 AI 分析"}</span>
            </label>`
          : ""
      }
      <div class="event-top">
        <div class="card-title">${escapeHtml(action)}</div>
        <div class="event-time">${escapeHtml(formatDateTime(log.timestamp))}</div>
      </div>
      <div class="event-grid">
        <span><strong>来源 IP：</strong>${escapeHtml(source)}</span>
        <span><strong>来源端口：</strong>${escapeHtml(log.source_port ?? "-")}</span>
        <span><strong>目标 IP：</strong>${escapeHtml(destination)}</span>
        <span><strong>目标端口：</strong>${escapeHtml(port)}</span>
      </div>
      <div class="event-message">${escapeHtml(log.message || "无日志消息")}</div>
      ${renderRawDetails(log.raw)}
      </div>
    </article>
  `;
}

function renderSearchPagination() {
  const prevButton = queryById("searchPrevBtn");
  const nextButton = queryById("searchNextBtn");
  const info = queryById("searchPaginationInfo");

  if (currentSearchMeta.page > 0) {
    const totalPages = Math.max(currentSearchMeta.totalPages, 1);
    info.textContent = `第 ${currentSearchMeta.page} / ${totalPages} 页，共 ${currentSearchMeta.total} 条，每页 ${currentSearchMeta.size} 条`;
  } else {
    info.textContent = "未开始分页查询。";
  }

  prevButton.disabled = !currentSearchMeta.hasPrev;
  nextButton.disabled = !currentSearchMeta.hasNext;
}

function renderSearchResults(data) {
  const logs = (data.logs || []).map(normalizeLog);
  currentSearchLogs = logs;
  currentSearchMeta = {
    total: data.total || 0,
    shown: logs.length,
    page: data.page || 1,
    size: data.size || logs.length || 0,
    totalPages: data.total_pages || 0,
    hasPrev: Boolean(data.has_prev),
    hasNext: Boolean(data.has_next),
  };
  renderSelectedState();
  renderSearchPagination();

  if (!logs.length) {
    setStatus("searchStatus", "查询完成，但没有命中日志。", "warning");
    renderEmptyState("searchResult", "没有符合条件的日志。");
    return;
  }

  queryById("searchResult").innerHTML = logs.map((log) => renderLogCard(log, { selectable: true })).join("");
  bindSearchLogSelection();
  setStatus("searchStatus", "查询成功，结果已更新。", "success");
}

function renderAlertCard(alert) {
  const severityText = alert.severity === "high" ? "高" : alert.severity === "medium" ? "中" : "低";
  const reasonLabels = Array.isArray(alert.reason_labels) ? alert.reason_labels : [];
  const typeLabel = alert.type === "aggregate" ? "聚合告警" : "事件告警";
  const destinationPort =
    alert.destination_port === null || alert.destination_port === undefined ? "-" : alert.destination_port;
  const extraInfo =
    alert.type === "aggregate"
      ? `<div class="event-message">${escapeHtml(
          `在 ${alert.window_minutes} 分钟内出现 ${alert.event_count} 次，样例端口：${(alert.sample_destination_ports || []).join(", ") || "-"}`
        )}</div>`
      : `<div class="event-message">${escapeHtml(alert.message || "无日志消息")}</div>`;

  return `
    <article class="event-card card log-card">
      <div class="card-body">
      <div class="event-top">
        <div class="card-title">${escapeHtml(typeLabel)}</div>
        <div class="badge severity-${escapeHtml(alert.severity || "low")}">${severityText}危</div>
      </div>
      <div class="meta chips">
        ${reasonLabels.map((label) => `<span class="chip">${escapeHtml(label)}</span>`).join("")}
      </div>
      <div class="event-grid">
        <span><strong>时间：</strong>${escapeHtml(formatDateTime(alert.timestamp))}</span>
        <span><strong>来源 IP：</strong>${escapeHtml(alert.source_ip || "-")}</span>
        <span><strong>来源端口：</strong>${escapeHtml(alert.source_port ?? "-")}</span>
        <span><strong>目标 IP：</strong>${escapeHtml(alert.destination_ip || "-")}</span>
        <span><strong>目标端口：</strong>${escapeHtml(destinationPort)}</span>
      </div>
      ${extraInfo}
      ${alert.type === "event" ? renderRawDetails(alert.raw) : ""}
      </div>
    </article>
  `;
}

function renderRangeLogs(logs) {
  if (!logs.length) {
    renderEmptyState("rangeLogsResult", "当前分析条件下没有可展示的日志。");
    return;
  }
  queryById("rangeLogsResult").innerHTML = logs.map((log) => renderLogCard(normalizeLog(log))).join("");
}

function renderDetectResult(data) {
  const alerts = data.alerts || [];
  const autoConfig = data.auto_analysis_settings || autoAnalysisSettings;
  const chips = [
    `检测窗口 ${data.window_minutes} 分钟`,
    `检查日志 ${data.total_logs || 0}`,
    `可疑事件 ${data.suspicious_count || 0}`,
    `当前返回 ${data.returned_alerts || alerts.length}`,
  ];
  if (typeof data.excluded_logs === "number" && data.excluded_logs > 0) {
    chips.push(`已排除 ${data.excluded_logs} 条`);
  }
  if (autoConfig) {
    chips.push(`自动分析${autoConfig.enabled ? "已启用" : "已关闭"}`);
  }
  if (data.logs_truncated) {
    chips.push("日志结果已截断");
  }
  renderChips("detectMeta", chips);
  renderSummaryText("aiSummary", data.ai_summary || "暂无检测结果。");

  if (!alerts.length) {
    renderEmptyState("detectResult", "当前没有可疑事件。");
  } else {
    queryById("detectResult").innerHTML = alerts.map(renderAlertCard).join("");
  }

  if (data.status === "error") {
    setStatus("detectStatus", data.message || "检测失败。", "error");
    return;
  }

  const suffix = data.logs_truncated ? " 已达到分析上限，建议缩小时间窗口。" : "";
  setStatus(
    "detectStatus",
    `最近一次检测时间：${formatDateTime(data.checked_at)}。${data.message || "检测完成。"}${suffix}`,
    alerts.length ? "success" : "warning"
  );
}

function renderRangeAnalysisResult(data) {
  const chips = [
    `开始 ${formatDateTime(data.requested_start)}`,
    `结束 ${formatDateTime(data.requested_end)}`,
    `分析日志 ${data.total_logs || 0}`,
  ];
  if (data.requested_source_ip) {
    chips.push(
      `来源 IP ${data.requested_source_ip_mode === "prefix" ? "前缀" : "精确"} ${data.requested_source_ip}`
    );
  }
  if (data.requested_destination_ip) {
    chips.push(
      `目标 IP ${data.requested_destination_ip_mode === "prefix" ? "前缀" : "精确"} ${data.requested_destination_ip}`
    );
  }
  if (Array.isArray(data.excluded_source_ip_prefixes) && data.excluded_source_ip_prefixes.length) {
    chips.push(`屏蔽来源 ${data.excluded_source_ip_prefixes.join(", ")}`);
  }
  if (data.logs_truncated) {
    chips.push("日志结果已截断");
  }
  renderChips("rangeMeta", chips);
  renderSummaryText("rangeSummary", data.summary || "AI 未返回内容。");
  renderRangeLogs(data.logs || []);
  setStatus(
    "rangeStatus",
    `分析完成：${formatDateTime(data.checked_at)}。${data.message || ""}`,
    "success"
  );
}

function renderSelectedAnalysisResult(data) {
  const chips = [
    `已选日志 ${data.total_logs || 0} 条`,
    `完成时间 ${formatDateTime(data.checked_at)}`,
  ];
  renderChips("selectedAnalysisMeta", chips);
  renderSummaryText("selectedSummary", data.summary || "AI 未返回内容。");
  setStatus("selectedAnalysisStatus", data.message || "已选日志分析完成。", "success");
}

function renderAutoAnalysisSettings(data, type = "neutral") {
  autoAnalysisSettings = {
    enabled: Boolean(data.enabled),
    interval_minutes: Number(data.interval_minutes || 10),
    exclude_source_ip_prefixes: Array.isArray(data.exclude_source_ip_prefixes) ? data.exclude_source_ip_prefixes : [],
    exclude_destination_ip_prefixes: Array.isArray(data.exclude_destination_ip_prefixes)
      ? data.exclude_destination_ip_prefixes
      : [],
    exclude_event_actions: Array.isArray(data.exclude_event_actions) ? data.exclude_event_actions : [],
    exclude_message_keywords: Array.isArray(data.exclude_message_keywords) ? data.exclude_message_keywords : [],
  };

  queryById("autoAnalysisEnabled").checked = autoAnalysisSettings.enabled;
  queryById("autoAnalysisInterval").value = String(autoAnalysisSettings.interval_minutes);
  queryById("autoExcludeSourceIps").value = autoAnalysisSettings.exclude_source_ip_prefixes.join(", ");
  queryById("autoExcludeDestinationIps").value = autoAnalysisSettings.exclude_destination_ip_prefixes.join(", ");
  queryById("autoExcludeActions").value = autoAnalysisSettings.exclude_event_actions.join(", ");
  queryById("autoExcludeKeywords").value = autoAnalysisSettings.exclude_message_keywords.join(", ");
  queryById("detectMinutes").value = String(autoAnalysisSettings.interval_minutes);
  appRoot.dataset.defaultWindowMinutes = String(autoAnalysisSettings.interval_minutes);

  const chips = [
    autoAnalysisSettings.enabled ? "自动分析已启用" : "自动分析已关闭",
    `间隔 ${autoAnalysisSettings.interval_minutes} 分钟`,
  ];
  if (autoAnalysisSettings.exclude_source_ip_prefixes.length) {
    chips.push(`排除来源 ${autoAnalysisSettings.exclude_source_ip_prefixes.join(", ")}`);
  }
  if (autoAnalysisSettings.exclude_destination_ip_prefixes.length) {
    chips.push(`排除目标 ${autoAnalysisSettings.exclude_destination_ip_prefixes.join(", ")}`);
  }
  if (autoAnalysisSettings.exclude_event_actions.length) {
    chips.push(`排除动作 ${autoAnalysisSettings.exclude_event_actions.join(", ")}`);
  }
  if (autoAnalysisSettings.exclude_message_keywords.length) {
    chips.push(`排除关键词 ${autoAnalysisSettings.exclude_message_keywords.join(", ")}`);
  }

  setStatus("autoAnalysisStatus", data.message || "自动分析设置已加载。", type);
  renderChips("autoAnalysisMeta", chips);
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });
  const rawText = await response.text();
  let data = {};

  if (rawText) {
    try {
      data = JSON.parse(rawText);
    } catch {
      data = { detail: rawText };
    }
  }

  if (!response.ok) {
    throw new Error(data.detail || data.message || `请求失败（${response.status}）`);
  }
  return data;
}

function readSearchForm() {
  const sourceIp = queryById("searchIp").value.trim();
  const sourceIpMode = queryById("searchIpMode").value;
  const destinationIp = queryById("searchDestinationIp").value.trim();
  const destinationIpMode = queryById("searchDestinationIpMode").value;
  const excludeIps = queryById("searchExcludeIps").value.trim();
  const start = toIso(queryById("searchStart").value);
  const end = toIso(queryById("searchEnd").value);
  const size = Number(queryById("searchSize").value || "100");

  return {
    sourceIp,
    sourceIpMode,
    destinationIp,
    destinationIpMode,
    excludeIps,
    start,
    end,
    size,
  };
}

function buildSearchParams(searchRequest) {
  const params = new URLSearchParams();
  if (searchRequest.sourceIp) params.set("source_ip", searchRequest.sourceIp);
  if (searchRequest.sourceIp) params.set("source_ip_mode", searchRequest.sourceIpMode);
  if (searchRequest.destinationIp) params.set("destination_ip", searchRequest.destinationIp);
  if (searchRequest.destinationIp) params.set("destination_ip_mode", searchRequest.destinationIpMode);
  if (searchRequest.excludeIps) params.set("exclude_source_ip_prefixes", searchRequest.excludeIps);
  if (searchRequest.start) params.set("start", searchRequest.start);
  if (searchRequest.end) params.set("end", searchRequest.end);
  params.set("page", String(searchRequest.page));
  params.set("size", String(searchRequest.size));
  return params;
}

async function runSearch(searchRequest) {
  const { start, end, size } = searchRequest;

  if (start && end && new Date(start) > new Date(end)) {
    setStatus("searchStatus", "开始时间不能晚于结束时间。", "error");
    return;
  }

  if (!Number.isFinite(size) || size < 1 || size > 1000) {
    setStatus("searchStatus", "每页返回条数必须在 1 到 1000 之间。", "error");
    return;
  }

  currentSearchRequest = { ...searchRequest };
  const params = buildSearchParams(searchRequest);

  setButtonLoading("searchBtn", true, "查询中...");
  setStatus("searchStatus", "正在查询日志...", "neutral");

  try {
    const data = await requestJson(`/api/search?${params.toString()}`);
    currentSearchRequest = { ...searchRequest, page: data.page || searchRequest.page, size: data.size || searchRequest.size };
    renderSearchResults(data);
  } catch (error) {
    currentSearchLogs = [];
    currentSearchMeta = { total: 0, shown: 0, page: 0, size: 0, totalPages: 0, hasPrev: false, hasNext: false };
    renderSelectedState();
    renderSearchPagination();
    setStatus("searchStatus", error.message || "查询失败。", "error");
    renderEmptyState("searchResult", "查询失败，请检查筛选条件或后端状态。");
  } finally {
    setButtonLoading("searchBtn", false, "查询日志");
  }
}

async function searchLogs() {
  await runSearch({ ...readSearchForm(), page: 1 });
}

async function changeSearchPage(delta) {
  if (!currentSearchRequest) {
    setStatus("searchStatus", "请先执行一次查询。", "warning");
    return;
  }

  const nextPage = currentSearchRequest.page + delta;
  if (nextPage < 1) return;
  if (currentSearchMeta.totalPages > 0 && nextPage > currentSearchMeta.totalPages) return;
  await runSearch({ ...currentSearchRequest, page: nextPage });
}

function copySearchConditionsToRange() {
  queryById("rangeStart").value = queryById("searchStart").value;
  queryById("rangeEnd").value = queryById("searchEnd").value;
  queryById("rangeIp").value = queryById("searchIp").value;
  queryById("rangeIpMode").value = queryById("searchIpMode").value;
  queryById("rangeDestinationIp").value = queryById("searchDestinationIp").value;
  queryById("rangeDestinationIpMode").value = queryById("searchDestinationIpMode").value;
  queryById("rangeExcludeIps").value = queryById("searchExcludeIps").value;
  queryById("rangeSize").value = queryById("searchSize").value || "100";
  setActiveView("aiView");
  setStatus("rangeStatus", "已同步当前查询条件，可直接开始分析。", "neutral");
}

async function deleteLogsBefore() {
  const before = toIso(queryById("deleteBefore").value);
  const ip = queryById("deleteIp").value.trim();
  const ipMode = queryById("deleteIpMode").value;

  if (!before) {
    setStatus("deleteStatus", "请先选择删除时间。", "error");
    return;
  }

  const filterText = ip ? `，且 IP ${ipMode === "prefix" ? "前缀" : "精确匹配"}为 ${ip}` : "";
  const confirmed = window.confirm(
    `确认删除 ${formatDateTime(before)} 之前的日志${filterText}？此操作不可撤销。`
  );
  if (!confirmed) {
    setStatus("deleteStatus", "已取消日志清理。", "warning");
    return;
  }

  setButtonLoading("deleteLogsBtn", true, "删除中...");
  setStatus("deleteStatus", "正在删除日志...", "neutral");

  try {
    const data = await requestJson("/api/logs/delete-before", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ before, ip: ip || null, ip_mode: ipMode }),
    });
    setStatus("deleteStatus", data.message || "日志清理完成。", "success");
    setStatus("searchStatus", "日志已清理，当前查询结果可能已过期，请重新查询。", "warning");
  } catch (error) {
    setStatus("deleteStatus", error.message || "日志清理失败。", "error");
  } finally {
    setButtonLoading("deleteLogsBtn", false, "删除符合条件的日志");
  }
}

function selectAllCurrentLogs() {
  currentSearchLogs.forEach((log) => {
    selectedLogs.set(getLogKey(log), log);
  });
  renderSelectedState();
  renderSearchResults({
    total: currentSearchMeta.total,
    page: currentSearchMeta.page,
    size: currentSearchMeta.size,
    total_pages: currentSearchMeta.totalPages,
    has_prev: currentSearchMeta.hasPrev,
    has_next: currentSearchMeta.hasNext,
    logs: currentSearchLogs,
  });
}

function clearSelectedLogs() {
  selectedLogs.clear();
  renderSelectedState();
  if (currentSearchLogs.length) {
    renderSearchResults({
      total: currentSearchMeta.total,
      page: currentSearchMeta.page,
      size: currentSearchMeta.size,
      total_pages: currentSearchMeta.totalPages,
      has_prev: currentSearchMeta.hasPrev,
      has_next: currentSearchMeta.hasNext,
      logs: currentSearchLogs,
    });
  }
}

async function analyzeSelectedLogs() {
  const logs = Array.from(selectedLogs.values()).map(serializeLogForApi);
  if (!logs.length) {
    setStatus("selectedAnalysisStatus", "请先在“查找日志”里勾选要分析的日志。", "warning");
    renderSummaryText("selectedSummary", "当前没有可分析的已选日志。");
    setActiveView("aiView");
    return;
  }

  setActiveView("aiView");
  setButtonLoading("analyzeSelectedBtn", true, "分析中...");
  setButtonLoading("analyzeSelectedFromAiBtn", true, "分析中...");
  setStatus("selectedAnalysisStatus", "正在分析已选日志...", "neutral");
  renderSummaryText("selectedSummary", "等待 AI 生成总结...");

  try {
    const data = await requestJson("/api/ai/analyze/selected", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ selected_logs: logs }),
    });
    renderSelectedAnalysisResult(data);
  } catch (error) {
    setStatus("selectedAnalysisStatus", error.message || "已选日志分析失败。", "error");
    renderSummaryText("selectedSummary", "已选日志分析失败，请检查 AI 配置或后端日志。");
  } finally {
    setButtonLoading("analyzeSelectedBtn", false, "分析已选日志");
    setButtonLoading("analyzeSelectedFromAiBtn", false, "分析已选日志");
  }
}

async function analyzeCustomRange() {
  const start = toIso(queryById("rangeStart").value);
  const end = toIso(queryById("rangeEnd").value);
  const sourceIp = queryById("rangeIp").value.trim();
  const sourceIpMode = queryById("rangeIpMode").value;
  const destinationIp = queryById("rangeDestinationIp").value.trim();
  const destinationIpMode = queryById("rangeDestinationIpMode").value;
  const excludeSourceIpPrefixes = splitCsv(queryById("rangeExcludeIps").value);
  const size = Number(queryById("rangeSize").value || "200");
  if (!start || !end) {
    setStatus("rangeStatus", "请填写开始时间和结束时间。", "error");
    return;
  }
  if (new Date(start) > new Date(end)) {
    setStatus("rangeStatus", "开始时间不能晚于结束时间。", "error");
    return;
  }
  if (!Number.isFinite(size) || size < 1 || size > 10000) {
    setStatus("rangeStatus", "分析条数上限必须在 1 到 10000 之间。", "error");
    return;
  }

  setButtonLoading("rangeAnalyzeBtn", true, "分析中...");
  setStatus("rangeStatus", "正在执行自定义时间分析...", "neutral");
  renderSummaryText("rangeSummary", "等待 AI 生成总结...");

  try {
    const data = await requestJson("/api/ai/analyze/range", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        start,
        end,
        size,
        source_ip: sourceIp || null,
        source_ip_mode: sourceIpMode,
        destination_ip: destinationIp || null,
        destination_ip_mode: destinationIpMode,
        exclude_source_ip_prefixes: excludeSourceIpPrefixes,
      }),
    });
    renderRangeAnalysisResult(data);
  } catch (error) {
    setStatus("rangeStatus", error.message || "自定义时间分析失败。", "error");
    renderSummaryText("rangeSummary", "自定义时间分析失败，请检查时间范围、AI 配置或后端日志。");
    renderEmptyState("rangeLogsResult", "自定义时间分析失败，未获取到日志。");
  } finally {
    setButtonLoading("rangeAnalyzeBtn", false, "开始自定义时间分析");
  }
}

async function analyzeCurrentSearchConditions() {
  copySearchConditionsToRange();
  await analyzeCustomRange();
}

async function manualDetect() {
  const minutes = Number(queryById("detectMinutes").value || appRoot.dataset.defaultWindowMinutes || "10");
  if (!Number.isFinite(minutes) || minutes < 1 || minutes > 1440) {
    setStatus("detectStatus", "检测窗口必须是 1 到 1440 之间的整数分钟。", "error");
    return;
  }

  setButtonLoading("manualDetectBtn", true, "分析中...");
  setStatus("detectStatus", "正在执行最近窗口分析...", "neutral");

  try {
    const params = new URLSearchParams({ minutes: String(minutes) });
    const data = await requestJson(`/api/detect/manual?${params.toString()}`, { method: "POST" });
    renderDetectResult(data);
  } catch (error) {
    setStatus("detectStatus", error.message || "最近窗口分析失败。", "error");
    renderChips("detectMeta", []);
    renderSummaryText("aiSummary", "最近窗口分析失败，暂无 AI 总结。");
    renderEmptyState("detectResult", "最近窗口分析失败，请检查 Elasticsearch、AI 配置或后端日志。");
  } finally {
    setButtonLoading("manualDetectBtn", false, "立即分析最近窗口");
  }
}

async function refreshLatest() {
  if (latestRefreshInFlight) return;
  latestRefreshInFlight = true;
  setButtonLoading("refreshLatestBtn", true, "刷新中...");

  try {
    const data = await requestJson("/api/detect/latest");
    renderDetectResult(data);
  } catch (error) {
    setStatus("detectStatus", `刷新最新结果失败：${error.message || "未知错误"}`, "error");
  } finally {
    latestRefreshInFlight = false;
    setButtonLoading("refreshLatestBtn", false, "刷新最新结果");
  }
}

async function loadHealth() {
  try {
    const data = await requestJson("/api/health");
    const elasticsearchStatus = data.services?.elasticsearch?.status || "unknown";
    const aiStatus = data.services?.ai?.status || "unknown";
    const schedulerEnabled = data.services?.scheduler?.status === "enabled";
    const schedulerRunning = !schedulerEnabled
      ? "已关闭"
      : data.services?.scheduler?.running
        ? "运行中"
        : "未运行";
    const schedulerInterval = data.services?.scheduler?.interval_minutes;
    const label = data.status === "ok" ? "success" : "warning";
    setStatus(
      "systemStatus",
      `系统状态：${data.status} | Elasticsearch：${elasticsearchStatus} | AI：${aiStatus} | 定时任务：${schedulerRunning}${schedulerInterval ? `（${schedulerInterval} 分钟）` : ""}`,
      label
    );
  } catch (error) {
    setStatus("systemStatus", `系统状态检查失败：${error.message || "未知错误"}`, "error");
  }
}

function renderAiStatus(data, typeOverride) {
  const configured = data.status !== "not_configured";
  const type =
    typeOverride || (data.connected === true ? "success" : configured ? "warning" : "error");
  const statusText =
    data.connected === true ? "已连接" : configured ? "已配置，待测试" : "未配置";

  setStatus("aiStatus", `AI 状态：${statusText}。${data.message || ""}`, type);
  renderChips("aiMeta", [`模型 ${data.model || "-"}`, `接口 ${data.base_url || "-"}`]);

  if (data.request_message) {
    renderSummaryText("aiTestRequest", data.request_message);
  }
  if (data.response_message) {
    renderSummaryText("aiTestResponse", data.response_message);
  }
}

async function loadAiStatus() {
  try {
    const data = await requestJson("/api/ai/status");
    renderAiStatus(data);
  } catch (error) {
    setStatus("aiStatus", `AI 状态检查失败：${error.message || "未知错误"}`, "error");
    renderChips("aiMeta", []);
  }
}

async function loadAutoAnalysisSettings() {
  try {
    const data = await requestJson("/api/auto-analysis/settings");
    renderAutoAnalysisSettings(data, "neutral");
  } catch (error) {
    setStatus("autoAnalysisStatus", error.message || "自动分析设置加载失败。", "error");
    renderChips("autoAnalysisMeta", []);
  }
}

async function saveAutoAnalysisSettings() {
  const intervalMinutes = Number(queryById("autoAnalysisInterval").value || "10");
  const excludeSourceIpPrefixes = splitCsv(queryById("autoExcludeSourceIps").value);
  const excludeDestinationIpPrefixes = splitCsv(queryById("autoExcludeDestinationIps").value);
  const excludeEventActions = splitCsv(queryById("autoExcludeActions").value);
  const excludeMessageKeywords = splitCsv(queryById("autoExcludeKeywords").value);

  if (!Number.isFinite(intervalMinutes) || intervalMinutes < 1 || intervalMinutes > 1440) {
    setStatus("autoAnalysisStatus", "自动分析间隔必须是 1 到 1440 之间的整数分钟。", "error");
    return;
  }

  setButtonLoading("saveAutoAnalysisSettingsBtn", true, "保存中...");
  setStatus("autoAnalysisStatus", "正在保存自动分析设置并刷新任务...", "neutral");

  try {
    const data = await requestJson("/api/auto-analysis/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        enabled: queryById("autoAnalysisEnabled").checked,
        interval_minutes: intervalMinutes,
        exclude_source_ip_prefixes: excludeSourceIpPrefixes,
        exclude_destination_ip_prefixes: excludeDestinationIpPrefixes,
        exclude_event_actions: excludeEventActions,
        exclude_message_keywords: excludeMessageKeywords,
      }),
    });
    renderAutoAnalysisSettings(data, "success");
    await refreshLatest();
    await loadHealth();
  } catch (error) {
    setStatus("autoAnalysisStatus", error.message || "自动分析设置保存失败。", "error");
  } finally {
    setButtonLoading("saveAutoAnalysisSettingsBtn", false, "保存自动分析设置");
  }
}

async function testAiConnection() {
  const message = queryById("aiTestMessage").value.trim();
  const requestMessage = message || "这是一次连接测试，请用简体中文简短回复“AI连接正常”。";

  setButtonLoading("aiTestBtn", true, "测试中...");
  setStatus("aiStatus", "正在向 AI 发送测试消息...", "neutral");
  renderSummaryText("aiTestRequest", requestMessage);
  renderSummaryText("aiTestResponse", "等待 AI 回复...");

  try {
    const params = new URLSearchParams({ message: requestMessage });
    const data = await requestJson(`/api/ai/test?${params.toString()}`, { method: "POST" });
    renderAiStatus(data, "success");
  } catch (error) {
    setStatus("aiStatus", error.message || "AI 连接测试失败。", "error");
    renderSummaryText("aiTestResponse", "AI 测试失败，请检查 API Key、模型名或网络连通性。");
  } finally {
    setButtonLoading("aiTestBtn", false, "测试 AI 连接");
  }
}

function initializeDateInputs() {
  const end = new Date();
  const start = new Date(end.getTime() - 60 * 60 * 1000);
  queryById("searchStart").value = formatForInput(start);
  queryById("searchEnd").value = formatForInput(end);
  queryById("rangeStart").value = formatForInput(start);
  queryById("rangeEnd").value = formatForInput(end);
}

document.querySelectorAll(".menu-btn").forEach((button) => {
  button.addEventListener("click", () => setActiveView(button.dataset.view));
});
queryById("searchBtn").addEventListener("click", searchLogs);
queryById("searchPrevBtn").addEventListener("click", () => changeSearchPage(-1));
queryById("searchNextBtn").addEventListener("click", () => changeSearchPage(1));
queryById("analyzeSearchRangeBtn").addEventListener("click", analyzeCurrentSearchConditions);
queryById("deleteLogsBtn").addEventListener("click", deleteLogsBefore);
queryById("selectAllLogsBtn").addEventListener("click", selectAllCurrentLogs);
queryById("clearSelectedLogsBtn").addEventListener("click", clearSelectedLogs);
queryById("analyzeSelectedBtn").addEventListener("click", analyzeSelectedLogs);
queryById("analyzeSelectedFromAiBtn").addEventListener("click", analyzeSelectedLogs);
queryById("clearSelectedFromAiBtn").addEventListener("click", clearSelectedLogs);
queryById("manualDetectBtn").addEventListener("click", manualDetect);
queryById("refreshLatestBtn").addEventListener("click", refreshLatest);
queryById("rangeAnalyzeBtn").addEventListener("click", analyzeCustomRange);
queryById("useSearchConditionsBtn").addEventListener("click", copySearchConditionsToRange);
queryById("aiTestBtn").addEventListener("click", testAiConnection);
queryById("saveAutoAnalysisSettingsBtn").addEventListener("click", saveAutoAnalysisSettings);

initializeDateInputs();
renderSelectedState();
renderSearchPagination();
loadHealth();
loadAiStatus();
loadAutoAnalysisSettings();
refreshLatest();
setInterval(refreshLatest, Math.max(autoRefreshSeconds, 15) * 1000);
setInterval(loadHealth, Math.max(autoRefreshSeconds, 15) * 1000);
setInterval(loadAiStatus, Math.max(autoRefreshSeconds, 15) * 1000);
