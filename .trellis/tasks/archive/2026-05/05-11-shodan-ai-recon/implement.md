# implement.md

## Implementation Checklist

- [x] 配置层
  - [x] 在 `config/__init__.py` 增加 `ShodanConfig` 和 `userinfo.shodan_api_key`。
  - [x] 更新 `config/settings.yaml` 示例。
  - [x] 更新 `fofamap.py init` 向导，Shodan Key 可选填写。
- [x] Shodan API 层
  - [x] 新增 `core/shodan_client.py`。
  - [x] 实现 `resolve_api_key`、`search(query, limit)`、`host_search(ip)`。
  - [x] 实现 401/403/429/网络异常的清晰错误日志。
- [x] Shodan 业务层
  - [x] 新增 `core/shodan_handler.py`。
  - [x] 实现搜索结果归一化为统一资产字段。
  - [x] 实现 Shodan 搜索展示、导出、0 结果提示。
  - [x] 实现 Shodan Host 控制台画像和 CVE 摘要。
  - [x] 实现 Shodan 专属资产报告/Host 风险画像写入。
  - [x] 实现明确扫描时仅筛选 HTTP(S) 目标联动 Nuclei。
- [x] AI 路由
  - [x] 更新 `DeepSeekHandler.strategic_planning` prompt，加入 `engine` 和 Shodan 路由规则。
  - [x] 新增 `normalize_ai_plan`，兼容旧 action 与 Shodan action 别名。
  - [x] 新增/抽取 Shodan DSL 白名单检测与原样保留逻辑。
  - [x] 新增 Shodan 专属资产报告生成方法，避免 FOFA 标题误用。
- [x] CLI
  - [x] 新增 `--shodan-query`、`--shodan-host`、`--shodan-limit` 参数。
  - [x] `run_async` 中按 `engine/action` 路由到 `ShodanHandler` 或现有 `FofaHandler`。
  - [x] 保持无 Shodan 意图时默认 FOFA。
- [x] MCP
  - [x] 在 `mcp_server.py` 导入 Shodan 能力。
  - [x] 新增 `shodan_search_assets(query, limit, display_rows)`，返回 Markdown 表格。
  - [x] 新增 `shodan_host_profile(ip)`，返回 Markdown 摘要。
- [x] 文档
  - [x] 更新 README 的配置示例、CLI 示例、AI 示例、MCP 工具说明。
- [x] 测试/验证
  - [x] 增加轻量单元测试或脚本覆盖 plan 归一化、DSL 检测、Shodan 结果归一化、缺 key 路径。
  - [x] 运行 Python 编译检查。

## Validation

- `python3 -m compileall config core utils fofamap.py mcp_server.py`
- 若添加 pytest 测试：`python3 -m pytest`
- 手动无网/无 key 验证：
  - `python3 fofamap.py -ai "使用 shodan 搜索 product:nginx"` 应明确提示 Shodan Key 缺失。
  - 现有 FOFA CLI 参数解析不应被 Shodan 参数影响。
- 有 Shodan Key 时的可选验证：
  - `SHODAN_API_KEY=... python3 fofamap.py --shodan-query 'product:nginx country:US' --shodan-limit 5 --export-format csv`
  - `SHODAN_API_KEY=... python3 fofamap.py --shodan-host 8.8.8.8`

## Review Gates

- 实现前：确认本规划范围，不把 `engine=all`、MCP AI 自动路由、Shodan 反思重试混入首版。
- 实现中：每完成一层先做静态检查，再接下一层，避免跨层数据契约断裂。
- 完成前：确认 FOFA 默认路径没有被重命名或大改，README 与配置示例一致。

## Rollback Points

- 配置层完成后可独立回滚，不影响 FOFA。
- Shodan Client/Handler 新文件完成后可独立删除回滚。
- CLI/MCP 接入为最后阶段，若出现回归优先回退入口接线而不是删除底层能力。
