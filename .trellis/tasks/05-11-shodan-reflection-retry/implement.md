# implement.md

## Implementation Checklist

- [x] 为 Shodan 自动反思确定首版预算策略（单轮反思，最多 3 条候选 DSL）
- [x] 在 `core/ai.py` 中新增 `reflect_and_retry_shodan(...)`
- [x] 在 `core/shodan_handler.py` 中增加 0 结果触发逻辑和预算控制（覆盖 AI 模式中的自然语言与原生 Shodan DSL 场景）
- [x] 为 Shodan 反思结果增加去重/去空/日志输出
- [x] 更新测试，覆盖触发条件、预算和错误路径
- [x] 更新 `.trellis/spec/backend/integration-contracts.md`
- [x] 跑编译检查与测试

## Validation

- `python3 -m compileall config core utils fofamap.py mcp_server.py test/test_shodan_core.py`
- `python3 test/test_shodan_core.py`
- 如需真实联调：使用一条刻意难命中的 Shodan 自然语言查询验证是否自动反思

## Review Gates

- 不允许复用 FOFA 提示词原文直接生成 Shodan 查询
- 不允许在 429/401/403/网络异常时触发反思
- 不允许无限重试
