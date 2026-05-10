import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import settings
from core.ai import (
    extract_shodan_dsl,
    looks_like_fofa_dsl,
    normalize_ai_plan,
    normalize_shodan_retry_queries,
)
from core.shodan_client import ShodanAPIError, ShodanClient
from core.shodan_handler import ShodanHandler


class FakeShodanClient:
    def __init__(self, responses=None, error=None):
        self.responses = responses or {}
        self.error = error
        self.search_calls = []

    async def search(self, query, limit=100):
        self.search_calls.append({"query": query, "limit": limit})
        if self.error:
            raise self.error
        return self.responses.get(query, [])


class FakeAIHandler:
    def __init__(self, retry_queries=None, enable_report=False):
        self.retry_queries = retry_queries or []
        self.reflect_calls = []
        self.report_calls = []
        self.client = object() if enable_report else None

    async def reflect_and_retry_shodan(self, user_intent, failed_queries, max_queries=3):
        self.reflect_calls.append({
            "user_intent": user_intent,
            "failed_queries": list(failed_queries),
            "max_queries": max_queries,
        })
        return list(self.retry_queries[:max_queries])

    async def generate_shodan_asset_report(self, rows, query, ai_query, report_path):
        self.report_calls.append({
            "rows": rows,
            "query": query,
            "ai_query": ai_query,
            "report_path": report_path,
        })


class ShodanCoreTest(unittest.TestCase):
    @staticmethod
    def _sample_record(ip="1.2.3.4", port=443, product="nginx", title="Welcome"):
        return {
            "ip_str": ip,
            "port": port,
            "ssl": {"cert": {}},
            "http": {"title": title},
            "hostnames": ["example.com"],
            "location": {"country_name": "United States", "city": "New York"},
            "org": "Example Org",
            "product": product,
            "version": "1.24",
            "os": "Linux",
            "timestamp": "2026-05-11T00:00:00Z",
        }

    def test_normalize_ai_plan_supports_old_and_shodan_aliases(self):
        self.assertEqual(
            normalize_ai_plan({"action": "fofa_search", "queries": ["app=\"nginx\""]})["action"],
            "asset_search",
        )
        shodan = normalize_ai_plan({"action": "shodan_search", "queries": ["product:nginx"]})
        self.assertEqual(shodan["engine"], "shodan")
        self.assertEqual(shodan["action"], "asset_search")

        host = normalize_ai_plan({"action": "shodan_host", "target": "8.8.8.8"})
        self.assertEqual(host["engine"], "shodan")
        self.assertEqual(host["action"], "host_query")

    def test_extract_shodan_dsl_uses_whitelist_and_ignores_urls(self):
        self.assertEqual(
            extract_shodan_dsl("使用 shodan 搜索 product:nginx country:US"),
            "product:nginx country:US",
        )
        self.assertEqual(
            extract_shodan_dsl("使用 shodan 搜索 product:nginx country:US 并扫描一下"),
            "product:nginx country:US",
        )
        self.assertEqual(
            extract_shodan_dsl('使用 shodan 搜索 product:nginx city:"Atlantis"'),
            'product:nginx city:"Atlantis"',
        )
        self.assertEqual(extract_shodan_dsl("打开 https://example.com 看看"), "")
        self.assertEqual(extract_shodan_dsl("shodan search ssl.cert.subject.cn:example.com"), "ssl.cert.subject.cn:example.com")

    def test_fofa_dsl_detection(self):
        self.assertTrue(looks_like_fofa_dsl('app="nginx" && country="US"'))
        self.assertFalse(looks_like_fofa_dsl("product:nginx country:US"))

    def test_normalize_shodan_retry_queries_filters_noise_and_limits_budget(self):
        queries = [
            "",
            "```product:nginx country:US```",
            "建议改成 hostname:example.com",
            'app="nginx" && country="US"',
            "hostname:example.com",
            "ssl.cert.subject.cn:example.com",
            "product:nginx country:US",
            "product:apache country:US",
        ]
        result = normalize_shodan_retry_queries(
            queries,
            failed_queries=["product:nginx country:US"],
            max_queries=3,
        )
        self.assertEqual(
            result,
            ["hostname:example.com", "ssl.cert.subject.cn:example.com", "product:apache country:US"],
        )

    def test_shodan_key_prefers_env_when_config_placeholder(self):
        old = os.environ.get("SHODAN_API_KEY")
        old_config_key = getattr(settings.userinfo, "shodan_api_key", "")
        os.environ["SHODAN_API_KEY"] = "env-key-for-test"
        settings.userinfo.shodan_api_key = "your_shodan_api_key"
        try:
            self.assertEqual(ShodanClient.resolve_api_key(), "env-key-for-test")
        finally:
            settings.userinfo.shodan_api_key = old_config_key
            if old is None:
                os.environ.pop("SHODAN_API_KEY", None)
            else:
                os.environ["SHODAN_API_KEY"] = old

    def test_normalize_record_builds_http_host_and_fields(self):
        row = ShodanHandler.normalize_record({
            "ip_str": "1.2.3.4",
            "port": 443,
            "ssl": {"cert": {}},
            "http": {"title": "Welcome"},
            "hostnames": ["example.com"],
            "location": {"country_name": "United States", "city": "New York"},
            "org": "Example Org",
            "product": "nginx",
            "version": "1.24",
            "os": "Linux",
            "timestamp": "2026-05-11T00:00:00Z",
        })
        self.assertEqual(row[0], "shodan")
        self.assertEqual(row[1], "https://1.2.3.4")
        self.assertEqual(row[5], "Welcome")
        self.assertEqual(row[10], "nginx")

    def test_run_search_task_reflects_once_and_uses_hit_query_for_report(self):
        original_query = "product:rare appliance country:US"
        retry_one = 'product:"rare appliance"'
        retry_two = "product:nginx"

        fake_client = FakeShodanClient(
            responses={
                original_query: [],
                retry_one: [],
                retry_two: [self._sample_record(product="nginx", title="Recovered")],
            }
        )
        fake_ai = FakeAIHandler(retry_queries=[retry_one, retry_two], enable_report=True)

        handler = ShodanHandler(client=fake_client, enable_ai=False)
        handler.ai_handler = fake_ai

        with tempfile.TemporaryDirectory() as tmpdir:
            rows = asyncio.run(
                handler.run_search_task(
                    query=original_query,
                    limit=5,
                    outdir=tmpdir,
                    export_format="csv",
                    ai_query="使用 shodan 查找一个很冷门的 rare appliance",
                )
            )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][10], "nginx")
        self.assertEqual(
            [item["query"] for item in fake_client.search_calls],
            [original_query, retry_one, retry_two],
        )
        self.assertEqual(len(fake_ai.reflect_calls), 1)
        self.assertEqual(fake_ai.reflect_calls[0]["failed_queries"], [original_query])
        self.assertEqual(fake_ai.reflect_calls[0]["max_queries"], 3)
        self.assertEqual(len(fake_ai.report_calls), 1)
        self.assertEqual(fake_ai.report_calls[0]["query"], retry_two)

    def test_run_search_task_without_ai_query_does_not_reflect(self):
        original_query = "product:rare appliance country:US"
        fake_client = FakeShodanClient(responses={original_query: []})
        fake_ai = FakeAIHandler(retry_queries=["product:nginx"])

        handler = ShodanHandler(client=fake_client, enable_ai=False)
        handler.ai_handler = fake_ai

        with tempfile.TemporaryDirectory() as tmpdir:
            rows = asyncio.run(
                handler.run_search_task(
                    query=original_query,
                    limit=5,
                    outdir=tmpdir,
                    export_format="csv",
                    ai_query=None,
                )
            )

        self.assertEqual(rows, [])
        self.assertEqual([item["query"] for item in fake_client.search_calls], [original_query])
        self.assertEqual(len(fake_ai.reflect_calls), 0)

    def test_run_search_task_api_error_does_not_reflect(self):
        original_query = "product:nginx"
        fake_client = FakeShodanClient(error=ShodanAPIError("Shodan 认证失败或权限不足，请检查 API Key。"))
        fake_ai = FakeAIHandler(retry_queries=["product:apache"])

        handler = ShodanHandler(client=fake_client, enable_ai=False)
        handler.ai_handler = fake_ai

        with tempfile.TemporaryDirectory() as tmpdir:
            rows = asyncio.run(
                handler.run_search_task(
                    query=original_query,
                    limit=5,
                    outdir=tmpdir,
                    export_format="csv",
                    ai_query="使用 shodan 搜索 nginx",
                )
            )

        self.assertEqual(rows, [])
        self.assertEqual([item["query"] for item in fake_client.search_calls], [original_query])
        self.assertEqual(len(fake_ai.reflect_calls), 0)


if __name__ == "__main__":
    unittest.main()
