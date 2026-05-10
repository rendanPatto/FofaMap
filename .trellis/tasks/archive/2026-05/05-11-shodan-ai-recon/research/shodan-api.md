# Shodan API 研究摘要

## 来源

- Shodan 官方 REST API 文档：`https://developer.shodan.io/api`
- Shodan Book 开发者 API 说明：`https://book.shodan.io/developer-apis/shodan-api/`
- 用户提供参考项目：`https://github.com/nn0nkey/Fofa-MCP`

## 与本任务相关的 API 契约

### Host 信息

- Endpoint：`GET https://api.shodan.io/shodan/host/{ip}`
- 认证：query 参数 `key={YOUR_API_KEY}`
- 关键参数：
  - `history`：是否返回历史 banner，首版不启用。
  - `minify`：是否只返回基础信息，首版不启用，因为 Host 画像需要服务明细。
- 关键返回字段：`ip_str`、`org`、`isp`、`asn`、`country_name`、`city`、`ports`、`data`。
- `data` 是 banner/service 列表，服务项通常包含 `port`、`transport`、`product`、`version`、`os`、`timestamp`、`http.title`、`hostnames`、`domains`。

### 搜索资产

- Endpoint：`GET https://api.shodan.io/shodan/host/search`
- 认证：query 参数 `key={YOUR_API_KEY}`
- 参数：
  - `query`：Shodan 查询语法，支持 `filter:value`。
  - `page`：分页，每页约 100 条。
  - `minify`：默认会截断较大的字段；首版可使用 `minify=true`，因为不导出原始 banner。
  - `fields`：可指定返回字段；首版可不依赖该参数，统一在 Handler 归一化。
- 关键返回字段：`matches`、`total`，`matches` 中每条记录与 Host 的 service banner 结构接近。

## 实现约束

- 首版不使用 Shodan Python SDK，复用项目已有 `httpx.AsyncClient` 风格。
- Shodan 搜索分页通过 `--shodan-limit` 控制目标数量，内部按 100 条/页取数并截断。
- 官方文档说明搜索/分页可能消耗 query credits，因此首版不做自动反思重试，避免意外消耗额度。
- Host 查询中的 CVE/漏洞情报只能作为 Shodan 情报摘要展示，不应表述为本地已验证漏洞。
