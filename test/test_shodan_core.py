import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.ai import extract_shodan_dsl, looks_like_fofa_dsl, normalize_ai_plan
from core.shodan_client import ShodanClient
from core.shodan_handler import ShodanHandler


class ShodanCoreTest(unittest.TestCase):
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
        self.assertEqual(extract_shodan_dsl("打开 https://example.com 看看"), "")
        self.assertEqual(extract_shodan_dsl("shodan search ssl.cert.subject.cn:example.com"), "ssl.cert.subject.cn:example.com")

    def test_fofa_dsl_detection(self):
        self.assertTrue(looks_like_fofa_dsl('app="nginx" && country="US"'))
        self.assertFalse(looks_like_fofa_dsl("product:nginx country:US"))

    def test_shodan_key_prefers_env_when_config_placeholder(self):
        old = os.environ.get("SHODAN_API_KEY")
        os.environ["SHODAN_API_KEY"] = "env-key-for-test"
        try:
            self.assertEqual(ShodanClient.resolve_api_key(), "env-key-for-test")
        finally:
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


if __name__ == "__main__":
    unittest.main()
