# design.md

## Technical Design

### 设计目标

以最小可控改动加入 Shodan 数据源：新增 Shodan 专用 Client/Handler，保留现有 FOFA Client/Handler 行为；由 `fofamap.py` 在入口层根据 AI plan 或手动参数路由到对应 Handler。

### 关键边界

- `core/shodan_client.py`
  - 只负责 Shodan REST API 请求、key 检查、分页/limit、HTTP/API 错误处理。
  - 不负责导出、报告、Nuclei、终端展示。
- `core/shodan_handler.py`
  - 负责 Shodan 业务流程：搜索、Host 画像、结果归一化、导出、AI 报告、Nuclei 可扫描目标筛选。
  - 复用 `ExcelExporter`、`NucleiScanner`、`DeepSeekHandler`。
- `core/ai.py`
  - 更新 AI prompt，加入 `engine` 概念和 Shodan 规则。
  - 新增/暴露 plan 归一化函数，兼容旧格式和别名。
  - 新增 Shodan 专属资产报告/Host 风险画像生成能力，避免复用写死 FOFA 的标题。
- `fofamap.py`
  - 新增 CLI 参数并做顶层路由。
  - FOFA 默认行为保持不变。
- `mcp_server.py`
  - 只新增独立 Shodan MCP 工具。
  - 不改现有 MCP AI 军师自动路由。
- `config/__init__.py` / `config/settings.yaml`
  - 加 `userinfo.shodan_api_key` 和 `shodan.default_limit/timeout`。

### 数据流

```text
AI 自然语言
  -> DeepSeekHandler.strategic_planning
  -> normalize_ai_plan(plan)
  -> engine=shodan/action=asset_search|host_query
  -> ShodanHandler
  -> ShodanClient REST API
  -> normalize_*_record
  -> 控制台展示 / 导出 / AI 报告 / 可选 Nuclei
```

手动 CLI：

```text
--shodan-query/--shodan-host
  -> fofamap.py
  -> ShodanHandler
  -> ShodanClient
  -> 展示/导出/报告
```

MCP：

```text
mcp_server.py tool
  -> ShodanHandler 或 ShodanClient + 归一化方法
  -> Markdown 表格/摘要
```

### AI Plan 契约

内部统一格式：

```json
{
  "engine": "fofa | shodan",
  "action": "asset_search | host_query | stat_query | icon_query | bat_query",
  "target": "IP/File/URL 或 null",
  "queries": ["查询语句"],
  "fields": "逗号分隔字段，可为空",
  "run_nuclei": false,
  "nuclei_args": ""
}
```

兼容映射：

```text
无 engine                         -> engine=fofa
fofa_search                        -> fofa / asset_search
shodan_search                      -> shodan / asset_search
shodan_host                        -> shodan / host_query
host_query + engine=shodan         -> shodan / host_query
host_query + 无 engine             -> fofa / host_query
```

### Shodan DSL 检测

白名单字段示例：

```text
product, port, country, city, org, hostname, net, os,
ssl, http, vuln, has_vuln, before, after, hash, title,
asn, isp, tag, cloud.provider
```

规则：

- 用户语句中命中白名单 `field:` 形式时，抽取并保留 DSL 片段。
- `https://`、`http://` 不应被误判为 Shodan DSL。
- 检测到 FOFA 风格语法（如 `app="x" && country="US"`）且用户要求 Shodan 时，不静默翻译；提示用户改写或让 AI 生成自然语言查询。

### Shodan 统一资产字段

字段顺序：

```text
engine, host, ip, port, protocol, title, domain, country, city, org, product, version, os, timestamp
```

归一化规则：

- `engine`: 固定 `shodan`。
- `ip`: `ip_str`。
- `port`: `port`。
- `protocol`: 优先 `transport`；HTTP/HTTPS 可结合 `ssl`、`http`、端口推断。
- `host`:
  - 443 或存在 `ssl` → `https://ip[:port]`
  - 80 或存在 `http` → `http://ip[:port]`
  - 其它 → `ip:port`
- `title`: `http.title`。
- `domain`: `hostnames` / `domains` 拼接或取代表值。
- `country/city`: `location.country_name` / `location.city`。
- `org/product/version/os/timestamp`: 直接取 Shodan 字段，缺失为空。

### 错误处理

- 缺 Shodan Key：仅 Shodan 链路 fail-fast，提示 `userinfo.shodan_api_key` 或 `SHODAN_API_KEY`。
- Shodan HTTP 401/403：提示认证或权限问题。
- Shodan HTTP 429：提示频率/额度限制，不自动多轮重试。
- 网络异常：记录异常并返回空结果或失败信息。
- 0 结果：提示无数据和放宽建议，不触发 Shodan AI 反思。

### Nuclei 筛选

- `run_nuclei=false` 时不扫描。
- `run_nuclei=true` 时只传入 `host` 以 `http://` 或 `https://` 开头的资产。
- 非 HTTP 服务保留在导出和报告中，但不作为 Nuclei 目标。

### Rollout / Rollback

- Rollout：新增文件和入口分支，不重命名现有 FOFA 类，降低回归风险。
- Rollback：删除 `core/shodan_client.py`、`core/shodan_handler.py`，移除 CLI/MCP/config/AI prompt 中的 Shodan 分支即可恢复 FOFA-only 行为。
