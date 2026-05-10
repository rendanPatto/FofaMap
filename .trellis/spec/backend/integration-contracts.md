# Backend Integration Contracts

## Scenario: Shodan engine integration

### 1. Scope / Trigger

- Trigger: Adding a new external asset-intelligence engine that spans config, AI routing, CLI options, MCP tools, export fields, reports, and optional Nuclei scanning.
- Scope: Shodan search and Shodan single-IP host profile only. Do not imply multi-engine merge or automatic FOFA-to-Shodan translation.

### 2. Signatures

- CLI:
  - `python3 fofamap.py --shodan-query <query> [--shodan-limit <n>] [--export-format xlsx|csv] [-o <file>] [--outdir <dir>] [-n]`
  - `python3 fofamap.py --shodan-host <ip> [--outdir <dir>]`
  - `python3 fofamap.py -ai "使用 shodan ..." [--shodan-limit <n>] [-n]`
- Python modules:
  - `ShodanClient.search(query: str, limit: int = 100) -> list[dict]`
  - `ShodanClient.host_search(ip: str) -> dict`
  - `ShodanHandler.normalize_record(record: dict) -> list[str]`
  - `normalize_ai_plan(plan: dict, user_intent: str = "") -> dict`
- MCP tools:
  - `shodan_search_assets(query: str, limit: int = 100, display_rows: int = 25) -> str`
  - `shodan_host_profile(ip: str) -> str`

### 3. Contracts

- Config:
  - `userinfo.shodan_api_key`: optional string. Placeholder values must not override `SHODAN_API_KEY`.
  - `shodan.default_limit`: integer fallback for `--shodan-limit`.
  - `shodan.timeout`: integer Shodan API timeout in seconds.
- Environment:
  - `SHODAN_API_KEY`: optional fallback when `userinfo.shodan_api_key` is empty or placeholder.
- AI plan normalized shape:
  - `engine`: `fofa | shodan`
  - `action`: `asset_search | host_query | stat_query | icon_query | bat_query`
  - `queries`: list of query strings
  - `target`: IP/file/URL or null
  - `run_nuclei`: boolean
  - `nuclei_args`: string
- Shodan asset row fields, in order:
  - `engine, host, ip, port, protocol, title, domain, country, city, org, product, version, os, timestamp`

### 4. Validation & Error Matrix

- Missing Shodan key + Shodan route -> fail fast with setup instructions; do not fall back to FOFA.
- Shodan HTTP 401/403 -> report authentication/permission failure.
- Shodan HTTP 429 -> report rate/quota limit; do not auto-retry in a loop.
- Shodan search zero results -> report no data and suggest relaxing filters; do not run AI reflection.
- User explicitly asks Shodan with FOFA DSL -> do not silently translate; ask for Shodan DSL or natural language.
- Shodan Nuclei requested -> pass only `http://` or `https://` normalized hosts to Nuclei.

### 5. Good/Base/Bad Cases

- Good: `-ai "使用 shodan 搜索 product:nginx country:US"` preserves `product:nginx country:US` and uses `engine=shodan`.
- Base: `--shodan-query 'product:nginx' --shodan-limit 20` exports normalized rows and does not require FOFA login.
- Bad: `-ai '使用 shodan 搜索 app="nginx" && country="US"'` must not translate FOFA DSL into Shodan DSL automatically.

### 6. Tests Required

- `normalize_ai_plan` maps legacy `fofa_search` and Shodan aliases to the normalized contract.
- Shodan DSL extraction ignores URLs and preserves whitelisted filters.
- Shodan key resolution prefers `settings.yaml`, then `SHODAN_API_KEY`, while placeholders allow env fallback.
- Shodan record normalization builds HTTP(S) hosts correctly and preserves field order.
- CLI/MCP import and Python compile checks pass without a Shodan key.

### 7. Wrong vs Correct

#### Wrong

```python
# Silently uses FOFA even though user requested Shodan.
if not shodan_key:
    return await fofa_client.search(query)
```

#### Correct

```python
# Shodan route fails fast and explains how to configure the key.
if not shodan_key:
    raise ShodanConfigError(
        "未配置 Shodan API Key。请设置 userinfo.shodan_api_key 或 SHODAN_API_KEY。"
    )
```
