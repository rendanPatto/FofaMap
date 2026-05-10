# 增强 AI 智能侦察支持 Shodan

## Goal

在不破坏现有 FOFA 默认体验的前提下，为 FofaMap 增加 Shodan 数据源能力。首版重点增强 `1. 🔮 AI 智能侦察`：当用户明确说“使用 shodan”时，AI 能路由到 Shodan 资产搜索或单 IP 画像；同时补充手动 CLI 与 MCP 独立工具，便于调试和 Agent 调用。

## Background / Known Context

- 当前项目主链路为 `fofamap.py` → `core/handler.py::FofaHandler` → `core/client.py::FofaClient` → 导出 / AI 报告 / Nuclei / MCP。
- 当前 AI 决策位于 `core/ai.py::DeepSeekHandler.strategic_planning`，返回 `action`、`target`、`queries`、`fields`、`run_nuclei` 等字段，现状偏 FOFA-only。
- 当前 CLI 已有 `-ai/-q/-hq/-cq/-ico/-bq/-p/-n/-o/--outdir/--export-format` 等参数。
- 当前 MCP Server (`mcp_server.py`) 已暴露 FOFA 搜索、Host 聚合、统计、图标、AI 军师等工具，返回 Markdown 表格/摘要。
- 用户参考 `https://github.com/nn0nkey/Fofa-MCP`，希望借鉴 FOFA + Shodan 多引擎 MCP 思路，但本项目还要兼容 CLI、AI 决策、导出、报告与 Nuclei。
- Shodan 官方 REST API 使用 `https://api.shodan.io/shodan/host/search` 搜索资产，使用 `https://api.shodan.io/shodan/host/{ip}` 查询单 IP 服务画像；详见 `research/shodan-api.md`。

## Requirements

### AI 智能侦察

- 默认仍使用 FOFA；只有用户明确提到 `shodan` / `Shodan` / `使用 shodan` 等意图时才选择 Shodan。
- Shodan 首版支持两类 AI 动作：
  - 资产搜索：自然语言或 Shodan DSL → Shodan 查询 → 展示/导出/报告。
  - 单 IP 画像：目标 IP → Shodan Host API → 控制台展示 + AI Markdown 风险画像。
- AI 计划输出升级为 `engine + action`：
  - `engine`: `fofa | shodan`
  - `action`: `asset_search | host_query | stat_query | icon_query | bat_query`
- 必须兼容旧 AI 输出和常见别名：
  - `fofa_search` → `engine=fofa, action=asset_search`
  - `shodan_search` → `engine=shodan, action=asset_search`
  - `shodan_host` → `engine=shodan, action=host_query`
- Shodan 查询生成采用混合策略：
  - 命中 Shodan 常见 filter 白名单时，尽量保留用户原始 DSL。
  - 自然语言场景由 AI 生成 Shodan DSL。
  - 不做 FOFA DSL → Shodan DSL 的静默翻译。
- Shodan 搜索 0 结果时不做 AI 反思重试，只提示无数据和放宽建议。

### 配置

- `userinfo.shodan_api_key` 保存 Shodan API Key。
- 支持环境变量 `SHODAN_API_KEY`。
- API Key 读取优先级：`settings.yaml` > `SHODAN_API_KEY`。
- 新增顶层 `shodan` 配置块保存运行参数：
  - `default_limit`: 默认结果数量，建议 100。
  - `timeout`: Shodan 请求超时，建议 30 秒。
- 未配置 Shodan Key 时不影响 FOFA 功能；只有用户明确使用 Shodan 时才 fail-fast 报错。

### 手动 CLI

- 新增手动参数但不加入交互菜单：
  - `--shodan-query 'product:nginx country:US'`
  - `--shodan-host 8.8.8.8`
  - `--shodan-limit 100`
- `--shodan-limit` 独立控制 Shodan 搜索数量，不复用 FOFA 的 `--pages`。

### Shodan 搜索结果

- 搜索结果使用统一资产字段模型：
  - `engine, host, ip, port, protocol, title, domain, country, city, org, product, version, os, timestamp`
- `host` 构造规则：
  - HTTP(S) 服务尽量构造成 URL。
  - 非 HTTP 服务使用 `ip:port`。
- 搜索结果不导出 `vulns`，避免把情报匹配误读成已验证漏洞。
- Shodan 搜索后生成 Shodan 专属 AI 资产报告，标题和内容必须明确数据源为 Shodan。

### Shodan Host 画像

- 控制台展示基础信息、开放端口、服务产品/版本、HTTP 标题、主机名、更新时间。
- AI 可用时生成 Markdown 风险画像报告。
- Host 画像中可展示 CVE 摘要，但必须标注来自 Shodan 情报，未做本地验证。
- 首版不要求 Host 画像结构化导出。

### Nuclei 联动

- Shodan 默认只查询和导出。
- 只有用户明确要求扫描 / nuclei / 漏洞检测 / 扫一下时，才筛选 HTTP(S) 资产联动 Nuclei。
- Shodan 非 HTTP 服务不得直接塞入 Web 扫描目标。

### MCP

- 首版纳入 MCP，但只新增独立工具，不改 MCP AI 军师自动路由：
  - `shodan_search_assets(query: str, limit: int = 100, display_rows: int = 25)`
  - `shodan_host_profile(ip: str)`
- MCP 返回 Markdown 表格/摘要，保持与现有 FOFA MCP 工具风格一致。

## Acceptance Criteria

- [ ] FOFA 现有 CLI 行为不变：未提到 Shodan 的 `-ai` 和现有 `-q/-hq/-cq/-ico/-bq` 仍走原链路。
- [ ] `python3 fofamap.py -ai "使用 shodan 搜索 product:nginx country:US"` 能路由到 Shodan 搜索，并保留原生 Shodan DSL。
- [ ] `python3 fofamap.py -ai "使用 shodan 查一下美国的 nginx"` 能生成 Shodan DSL 并执行搜索。
- [ ] `python3 fofamap.py -ai "用 shodan 看看 8.8.8.8"` 能执行 Shodan Host 画像。
- [ ] `python3 fofamap.py --shodan-query 'product:nginx country:US' --shodan-limit 20` 能手动执行 Shodan 搜索。
- [ ] `python3 fofamap.py --shodan-host 8.8.8.8` 能手动执行 Shodan Host 画像。
- [ ] 未配置 Shodan Key 且用户明确使用 Shodan 时，输出明确配置提示，不回退 FOFA。
- [ ] Shodan 搜索结果可导出 xlsx/csv，字段为统一资产字段模型。
- [ ] Shodan 搜索后生成 Shodan 专属资产报告；报告不得写成 FOFA 数据源。
- [ ] Shodan Host 画像报告中的 CVE 摘要标注“来自 Shodan 情报，未本地验证”。
- [ ] MCP 新增 `shodan_search_assets` 和 `shodan_host_profile`，返回 Markdown。
- [ ] 项目通过至少 Python 语法编译检查；如新增测试，应通过测试。

## Definition of Done

- 新增或更新必要测试，覆盖 AI plan 归一化、Shodan DSL 检测、结果归一化、缺 key 错误路径等核心逻辑。
- 运行 Python 语法检查或项目可用测试命令。
- README / 配置示例同步更新。
- 不新增第三方依赖。
- 变更保持可回滚，不重构现有 FOFA 主链路。

## Out of Scope

- 不实现 `--engine all` 或 FOFA + Shodan 合并查询。
- 不做 FOFA 查询语法到 Shodan 查询语法的静默自动翻译。
- 不做 Shodan AI 自我反思重试。
- 不改 MCP AI 军师为自动 Shodan 路由。
- 不做 Shodan 统计聚合、批量文件模式、历史 Host 数据。
- 不引入官方 `shodan` Python SDK 或其他新第三方依赖。

## Research References

- `research/shodan-api.md`
