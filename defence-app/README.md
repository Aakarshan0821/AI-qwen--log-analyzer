# Defence App（ELK + 安全/服务器日志 + 千问）

这是一个基于 `FastAPI + Jinja2 + 原生 JavaScript` 的轻量 Web 应用，用于检索和分析 Elasticsearch 中的安全日志、网络日志和服务器日志。当前版本重点增强了 3 个方面：

1. 前端体验：日志与告警结果改为卡片化展示，增加加载、空态、错误态和系统健康状态提示。
2. 检测逻辑：支持分批拉取检测窗口日志，避免只分析固定前 2000 条；对同一事件的多条命中规则做归并去重。
3. AI 交互：前端可查看 AI 配置状态，支持一键发送测试消息验证连通性，并显示测试回复。
4. 稳定性：加入统一异常处理、健康检查接口、ES/AI 超时配置，并将单文件逻辑拆分为配置、服务、路由和状态模块。

详细使用、部署和运维说明见 `docs/usage-and-deployment.md`。

如需查看 `ELK Docker 部署`、`pfSense 远程日志接入`、`column 字段拆分`、`开机自启动` 和 `QWEN_API_KEY` 配置位置，请参考 `docs/elk-docker-pfsense-deployment.md`。

如需查看 `WAF / OPNsense / Nginx / Linux / Windows` 等多日志源兼容说明，请参考 `docs/multi-source-log-compatibility.md`。

## 目录结构

```text
defence-app/
├─ app/
│  ├─ api/routes.py
│  ├─ services/
│  │  ├─ ai_service.py
│  │  ├─ detection_service.py
│  │  └─ es_service.py
│  ├─ app_factory.py
│  ├─ config.py
│  ├─ errors.py
│  ├─ main.py
│  ├─ schemas.py
│  ├─ state.py
│  ├─ static/
│  │  ├─ app.js
│  │  └─ style.css
│  └─ templates/index.html
├─ tests/
│  ├─ test_detection_service.py
│  └─ test_es_service.py
├─ .env.example
└─ requirements.txt
```

## 运行环境

- Python 3.10+
- Elasticsearch 可访问，默认 `http://127.0.0.1:9200`
- 已有 Elasticsearch 日志索引，默认 `pfsense-*`

## 安装与启动

Windows PowerShell：

```powershell
cd "E:\信抗技术项目\defence-app"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Linux / macOS：

```bash
cd /home/user/defence-app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

启动服务：

```bash
uvicorn app.main:app --host 0.0.0.0 --port 7860
```

浏览器访问：

- `http://127.0.0.1:7860`

## Ubuntu 部署

如果你已经把项目上传并解压到 `/home/user/defence-app`，可以直接按下面步骤部署。

### 1. 进入项目目录

```bash
cd /home/user/defence-app
```

### 2. 创建 Python 虚拟环境

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. 安装依赖

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. 复制配置文件

```bash
cp .env.example .env
```

然后编辑 `.env`，至少确认以下配置正确：

```env
ES_URL=http://127.0.0.1:9200
ES_INDEX_PATTERN=pfsense-*
ES_USERNAME=
ES_PASSWORD=
```

如果你的 Elasticsearch 开启了认证，就改成：

```env
ES_USERNAME=elastic
ES_PASSWORD=你的密码
```

### 5. 启动项目

```bash
uvicorn app.main:app --host 0.0.0.0 --port 7860
```

### 6. 验证是否启动成功

浏览器访问：

- `http://127.0.0.1:7860`

命令行检查：

```bash
curl http://127.0.0.1:7860/api/health
```

如果返回 JSON，说明服务启动成功。

### 7. 后台长期运行

如果你不想每次开终端手动运行，推荐使用 `systemd`。下面是适配你当前目录的服务文件：

```ini
[Unit]
Description=Defence App
After=network.target

[Service]
Type=simple
User=user
WorkingDirectory=/home/user/defence-app
EnvironmentFile=/home/user/defence-app/.env
ExecStart=/home/user/defence-app/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 7860
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

保存到：

```bash
sudo nano /etc/systemd/system/defence-app.service
```

然后执行：

```bash
sudo systemctl daemon-reload
sudo systemctl enable defence-app
sudo systemctl start defence-app
sudo systemctl status defence-app
```

## 关键配置项

- `ES_URL`：Elasticsearch 地址
- `ES_INDEX_PATTERN`：日志索引模式，例如 `pfsense-*`
- `ES_TIMEOUT_SECONDS`：ES 请求超时秒数
- `ES_SEARCH_BATCH_SIZE`：分批读取日志时每批条数
- `DETECTION_MAX_LOGS`：单次检测最多分析的日志数
- `QWEN_API_KEY`：千问兼容接口密钥，不填则使用本地规则摘要
- `AI_TIMEOUT_SECONDS`：AI 请求超时秒数
- `DETECTION_WINDOW_MINUTES`：定时检测窗口分钟数
- `ENABLE_SCHEDULER`：是否启用内置定时任务
- `AUTO_REFRESH_SECONDS`：前端自动刷新最新检测结果的间隔秒数
- `SUSPICIOUS_THRESHOLD`：来源 IP 高频出现阈值
- `RISKY_PORTS`：高危目标端口列表
- `MAX_ALERTS_DISPLAY`：前端最多展示的告警条数

如果你使用多实例或多 worker 部署，建议将 `ENABLE_SCHEDULER=false`，避免重复触发定时任务。

## 核心接口

- `GET /`：主页
- `GET /api/search`：按时间/IP 查询日志
- `POST /api/detect/manual`：手动触发检测
- `GET /api/detect/latest`：获取最近一次检测结果
- `GET /api/ai/status`：获取 AI 配置状态
- `POST /api/ai/test`：向 AI 发送测试消息并返回回复
- `GET /api/health`：查看应用、调度器和 Elasticsearch 健康状态

## 检测逻辑

- `event.action == block` 判定为阻断流量
- 目标端口命中 `RISKY_PORTS` 判定为高危目标端口
- 单个来源 IP 在窗口内出现次数大于等于 `SUSPICIOUS_THRESHOLD`，追加高频来源 IP 聚合告警
- 同一条日志若同时命中多条规则，会归并为一条告警，并保留全部命中原因
- 检测使用分批分页拉取窗口数据；若达到 `DETECTION_MAX_LOGS` 上限，会在结果中标记 `logs_truncated=true`

## 测试

执行最小测试集：

```bash
python -m unittest discover -s tests
```

## 说明

- 当前没有引入大型前端框架，便于继续在现有结构上迭代。
- 若需要扩展更多规则，优先修改 `app/services/detection_service.py`。
- 若需要替换 ES 或 AI 策略，优先修改对应 `service` 模块，避免再回到单文件耦合结构。
