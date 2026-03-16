# ELK Docker + pfSense + Defence App 部署说明

## 1. 目标

本文档说明如何完成以下部署：

1. 使用 Docker Compose 部署 `Elasticsearch + Logstash + Kibana`
2. 让 `pfSense` 把日志转发到 Logstash
3. 在 Logstash 中为 pfSense 日志补充 `pfsense.columnN` 字段
4. 部署 `Defence App` 并连接 Elasticsearch
5. 配置 ELK 和 Defence App 开机自启动
6. 说明 `QWEN_API_KEY` 在哪里配置

本文档默认以 Ubuntu 服务器为例，目录示例：

```text
/opt/elk-pfsense
/opt/defence-app
```

## 2. 架构说明

推荐链路如下：

```text
pfSense --> UDP Syslog --> Logstash --> Elasticsearch --> Kibana
                                              |
                                              +--> Defence App
```

说明：

- `pfSense` 负责发送防火墙日志
- `Logstash` 负责接收、拆分字段、补充 `pfsense.columnN`
- `Elasticsearch` 负责存储和检索日志
- `Kibana` 负责查看索引和调试日志
- `Defence App` 直接查询 Elasticsearch 中的 `pfsense-*` 索引

## 3. 准备服务器

### 3.1 安装 Docker 与 Compose

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable docker
sudo systemctl start docker
docker --version
docker compose version
```

### 3.2 创建部署目录

```bash
sudo mkdir -p /opt/elk-pfsense/logstash/pipeline
sudo mkdir -p /opt/elk-pfsense/logstash/config
sudo chown -R $USER:$USER /opt/elk-pfsense
```

## 4. 使用 Docker Compose 部署 ELK

### 4.1 创建 `docker-compose.yml`

保存到 `/opt/elk-pfsense/docker-compose.yml`：

```yaml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.2
    container_name: elk-elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
    ports:
      - "9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data
    restart: unless-stopped

  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.2
    container_name: elk-kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    restart: unless-stopped

  logstash:
    image: docker.elastic.co/logstash/logstash:8.12.2
    container_name: elk-logstash
    environment:
      - LS_JAVA_OPTS=-Xms512m -Xmx512m
    ports:
      - "5140:5140/udp"
      - "9600:9600"
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
      - ./logstash/config:/usr/share/logstash/config
    depends_on:
      - elasticsearch
    restart: unless-stopped

volumes:
  esdata:
```

说明：

- `9200` 是 Elasticsearch HTTP 接口
- `5601` 是 Kibana 访问端口
- `5140/udp` 是 pfSense 远程 syslog 发送到 Logstash 的端口
- 这里关闭了 ES 内置认证，便于快速部署；如果你要开启认证，需要同步修改 Defence App 的 `.env`

### 4.2 创建 Logstash 配置

保存到 `/opt/elk-pfsense/logstash/config/logstash.yml`：

```yaml
http.host: "0.0.0.0"
xpack.monitoring.enabled: false
pipeline.ordered: auto
```

### 4.3 创建 pfSense 日志解析管道

保存到 `/opt/elk-pfsense/logstash/pipeline/pfsense.conf`：

```conf
input {
  udp {
    port => 5140
    type => "pfsense"
    codec => plain { charset => "UTF-8" }
  }
}

filter {
  grok {
    match => {
      "message" => [
        "^<%{POSINT:syslog_pri}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{HOSTNAME:[observer][name]} %{DATA:syslog_program}: %{GREEDYDATA:[event][original]}$",
        "^%{SYSLOGTIMESTAMP:syslog_timestamp} %{HOSTNAME:[observer][name]} %{DATA:syslog_program}: %{GREEDYDATA:[event][original]}$",
        "^%{DATA:syslog_program}: %{GREEDYDATA:[event][original]}$"
      ]
    }
    tag_on_failure => []
  }

  if ![event][original] {
    mutate {
      add_field => { "[event][original]" => "%{message}" }
    }
  }

  if [syslog_program] == "filterlog" or [message] =~ /filterlog/ {
    ruby {
      code => '
        raw = event.get("[event][original]")
        if raw
          raw.split(",").each_with_index do |value, idx|
            event.set("[pfsense][column#{idx + 1}]", value.to_s.strip)
          end
        end
      '
    }

    mutate {
      add_field => {
        "[observer][type]" => "pfsense"
        "[event][category]" => "network"
        "[pfsense][action]" => "%{[pfsense][column7]}"
        "[pfsense][direction]" => "%{[pfsense][column8]}"
        "[pfsense][ip_version]" => "%{[pfsense][column9]}"
        "[event][action]" => "%{[pfsense][column7]}"
      }
    }

    if [pfsense][ip_version] == "4" {
      mutate {
        add_field => {
          "[source][ip]" => "%{[pfsense][column19]}"
          "[destination][ip]" => "%{[pfsense][column20]}"
          "[source][port]" => "%{[pfsense][column21]}"
          "[destination][port]" => "%{[pfsense][column22]}"
        }
      }
    } else if [pfsense][ip_version] == "6" {
      mutate {
        add_field => {
          "[source][ip]" => "%{[pfsense][column16]}"
          "[destination][ip]" => "%{[pfsense][column17]}"
          "[source][port]" => "%{[pfsense][column18]}"
          "[destination][port]" => "%{[pfsense][column19]}"
        }
      }
    }
  }

  date {
    match => ["syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss"]
    timezone => "Asia/Shanghai"
    target => "@timestamp"
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    index => "pfsense-%{+YYYY.MM.dd}"
  }
}
```

### 4.4 为什么要添加 `column`

当前 Defence App 在查询 pfSense 日志时，会优先兼容这些字段：

- IPv4：
  - `pfsense.column19` -> 来源 IP
  - `pfsense.column20` -> 目标 IP
  - `pfsense.column21` -> 来源端口
  - `pfsense.column22` -> 目标端口
- IPv6：
  - `pfsense.column16` -> 来源 IP
  - `pfsense.column17` -> 目标 IP
  - `pfsense.column18` -> 来源端口
  - `pfsense.column19` -> 目标端口
- 通用：
  - `pfsense.action` 或 `event.action` -> 动作，例如 `block`、`pass`

上面的 Ruby 代码会把 pfSense `filterlog` 逗号分隔原始日志拆成：

- `pfsense.column1`
- `pfsense.column2`
- `pfsense.column3`
- ...

这样 Defence App 就可以直接兼容你写入 ES 的原始列位字段。

### 4.5 启动 ELK

```bash
cd /opt/elk-pfsense
docker compose up -d
docker compose ps
```

### 4.6 验证 ELK

检查 Elasticsearch：

```bash
curl http://127.0.0.1:9200
```

检查 Kibana：

- 浏览器访问 `http://服务器IP:5601`

检查 Logstash：

```bash
docker logs -f elk-logstash
```

## 5. pfSense 如何把日志发到 ELK

### 5.1 pfSense 页面位置

进入 pfSense 后台：

`Status -> System Logs -> Settings`

### 5.2 开启远程日志

按下面方式配置：

1. 勾选 `Enable Remote Logging`
2. 在 `Remote log servers` 中填写：
   - `你的Logstash服务器IP:5140`
3. 在日志内容中至少勾选：
   - `Firewall Events`
4. 如果你还想同步其他日志，也可以额外勾选：
   - DHCP
   - DNS
   - OpenVPN
   - System

建议：

- 优先发送 `Firewall Events`，因为当前 Defence App 主要分析的是 `filterlog`
- 如果 pfSense 支持选择日志格式，优先使用 `Syslog` 格式
- 如果只想先验证链路，先只勾选 `Firewall Events`

### 5.3 pfSense 原始 filterlog 常见列位

pfSense 官方 `filterlog` 采用逗号分隔格式，前面几列的含义通常是：

1. rule number
2. sub rule number
3. anchor
4. tracker
5. real interface
6. reason
7. action
8. direction
9. ip version

所以本文档中把：

- `column7` 映射到 `action`
- `column8` 映射到 `direction`
- `column9` 映射到 `ip_version`

而 IP 和端口列位则根据 IPv4 / IPv6 分开处理。

## 6. 如何确认日志已经进入 Elasticsearch

### 6.1 查看索引

```bash
curl "http://127.0.0.1:9200/_cat/indices?v"
```

你应该能看到类似：

```text
pfsense-2026.03.14
```

### 6.2 查看最近 5 条日志

```bash
curl "http://127.0.0.1:9200/pfsense-*/_search?pretty" -H "Content-Type: application/json" -d '{
  "size": 5,
  "sort": [
    { "@timestamp": { "order": "desc" } }
  ]
}'
```

重点确认返回文档中是否存在：

- `@timestamp`
- `message`
- `pfsense.column19` / `pfsense.column20`
- 或 `source.ip` / `destination.ip`
- `event.action`

### 6.3 Kibana 中验证

在 Kibana 的 `Discover` 页面中：

1. 创建索引模式 `pfsense-*`
2. 选择时间字段 `@timestamp`
3. 搜索 `filterlog`
4. 展开任意一条日志，查看是否已有 `pfsense.column19` 等字段

## 7. 部署 Defence App

### 7.1 上传或拷贝项目

假设项目目录是：

```bash
/opt/defence-app
```

### 7.2 安装依赖

```bash
cd /opt/defence-app
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

### 7.3 修改 `.env`

编辑项目根目录 `/opt/defence-app/.env`：

```env
ES_URL=http://127.0.0.1:9200
ES_INDEX_PATTERN=pfsense-*
ES_USERNAME=
ES_PASSWORD=

QWEN_API_KEY=你的千问APIKey
QWEN_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
QWEN_MODEL=qwen-plus
AI_TIMEOUT_SECONDS=30

ENABLE_SCHEDULER=true
AUTO_REFRESH_SECONDS=60
```

说明：

- 如果 Elasticsearch 没开认证，`ES_USERNAME` 和 `ES_PASSWORD` 留空即可
- 如果 Elasticsearch 开了认证，就在这里填账号密码
- `ES_INDEX_PATTERN` 必须与你 Logstash 写入的索引前缀一致

### 7.4 API Key 配置位置

`Defence App` 的 AI Key 配置位置是：

1. 模板文件：项目根目录 `.env.example`
2. 实际生效文件：项目根目录 `.env`
3. 读取代码位置：`app/config.py`

本项目对应配置项是：

```env
QWEN_API_KEY=你的千问APIKey
QWEN_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
QWEN_MODEL=qwen-plus
```

说明：

- 真正需要填写的是 `.env` 中的 `QWEN_API_KEY`
- `.env.example` 只是示例模板
- `app/config.py` 会在启动时通过环境变量读取 `QWEN_API_KEY`

### 7.5 启动 Defence App

```bash
cd /opt/defence-app
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 7860
```

浏览器访问：

- `http://服务器IP:7860`

### 7.6 验证 Defence App

```bash
curl http://127.0.0.1:7860/api/health
```

如果返回正常 JSON，再到网页中测试：

1. 查找日志
2. 最近窗口分析
3. 自定义时间分析
4. AI 测试连接

## 8. 如何配置开机自启动

### 8.1 Docker 服务开机自启

```bash
sudo systemctl enable docker
sudo systemctl start docker
```

### 8.2 ELK 使用 Docker 自恢复

在 `docker-compose.yml` 中已经写了：

```yaml
restart: unless-stopped
```

这表示：

- Docker 服务启动后，容器会自动恢复
- 如果容器异常退出，也会自动拉起

### 8.3 为 ELK 增加 systemd 管理

如果你希望通过 systemd 明确管理整套 ELK，可创建：

`/etc/systemd/system/elk-pfsense.service`

```ini
[Unit]
Description=ELK Stack for pfSense
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/elk-pfsense
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
```

启用：

```bash
sudo systemctl daemon-reload
sudo systemctl enable elk-pfsense
sudo systemctl start elk-pfsense
sudo systemctl status elk-pfsense
```

### 8.4 Defence App 开机自启动

创建：

`/etc/systemd/system/defence-app.service`

```ini
[Unit]
Description=Defence App
After=network.target docker.service

[Service]
Type=simple
User=user
WorkingDirectory=/opt/defence-app
EnvironmentFile=/opt/defence-app/.env
ExecStart=/opt/defence-app/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 7860
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

启用：

```bash
sudo systemctl daemon-reload
sudo systemctl enable defence-app
sudo systemctl start defence-app
sudo systemctl status defence-app
```

查看日志：

```bash
journalctl -u defence-app -f
```

注意：

- `User=user` 要改成你的实际运行用户
- `WorkingDirectory` 和 `ExecStart` 要改成你的真实路径
- 如果 Elasticsearch 也跑在本机，建议先启动 `elk-pfsense` 再启动 `defence-app`

## 9. 常见问题

### 9.1 Kibana 能打开，但 Defence App 查不到日志

先检查：

- `.env` 里的 `ES_INDEX_PATTERN` 是否为 `pfsense-*`
- 日志是否真的写进了这个索引
- 文档里是否有 `pfsense.column19`、`pfsense.column20`、`event.action`
- 查询时间范围是否正确

### 9.2 pfSense 已经发日志，但 ES 没有数据

先检查：

- pfSense 远程日志地址是否写成 `LogstashIP:5140`
- 服务器防火墙是否放行 UDP `5140`
- `docker logs -f elk-logstash` 是否有收到日志

### 9.3 没有 `column` 字段

说明 Logstash 没有正确执行拆分逻辑。重点检查：

- `pfsense.conf` 是否已挂载进容器
- 日志程序名是否是 `filterlog`
- 日志原文是否确实是逗号分隔的 pfSense filterlog

### 9.4 AI 无法连接

先检查：

- `/opt/defence-app/.env` 中是否填写了 `QWEN_API_KEY`
- `QWEN_BASE_URL` 是否正确
- 服务器是否可以访问外网 AI 接口

## 10. 最小验证清单

完成部署后，按顺序验证：

1. `docker compose ps` 正常
2. `curl http://127.0.0.1:9200` 正常
3. Kibana 可打开
4. pfSense 已开启远程日志
5. `pfsense-*` 索引已经生成
6. ES 文档中可看到 `pfsense.column19` 等字段
7. `curl http://127.0.0.1:7860/api/health` 正常
8. 页面可以查询到日志
9. `.env` 中已填写 `QWEN_API_KEY`
10. AI 测试按钮可以返回结果
