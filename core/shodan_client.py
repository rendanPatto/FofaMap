import math
import os
from typing import Any, Dict, List, Optional

import httpx

from config import settings
from utils.logger import logger


class ShodanConfigError(Exception):
    """Shodan 本地配置错误。"""


class ShodanAPIError(Exception):
    """Shodan API 请求错误。"""


class ShodanClient:
    """Shodan REST API 异步封装。

    该类只负责认证、请求和基础错误处理；结果归一化、导出和报告由
    ShodanHandler 负责，避免 API 层泄漏业务逻辑。
    """

    PAGE_SIZE = 100

    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://api.shodan.io"
        # 延迟解析 API Key，确保未使用 Shodan 时不会影响 FOFA 默认链路。
        self.api_key = api_key
        timeout = getattr(getattr(settings, "shodan", None), "timeout", 30)
        self.client_args = {"timeout": timeout}
        self.headers = {
            "User-Agent": "FofaMapV2/2.0 ShodanClient (By Hx0 Team)"
        }
        self.last_total = 0

    @staticmethod
    def resolve_api_key() -> str:
        """按 settings.yaml > SHODAN_API_KEY 的优先级解析 Shodan Key。"""
        configured = getattr(settings.userinfo, "shodan_api_key", "") or ""
        configured = str(configured).strip()

        # 示例占位符不应阻止用户通过环境变量注入真实 key。
        placeholders = {"your_shodan_api_key", "shodan_api_key", "changeme", "none", "null"}
        if configured and configured.lower() not in placeholders:
            return configured

        env_key = os.getenv("SHODAN_API_KEY", "").strip()
        if env_key:
            return env_key

        raise ShodanConfigError(
            "未配置 Shodan API Key。请在 config/settings.yaml 中设置 userinfo.shodan_api_key，"
            "或通过环境变量 SHODAN_API_KEY 配置。"
        )

    def _params(self, extra: Dict[str, Any]) -> Dict[str, Any]:
        if not self.api_key:
            self.api_key = self.resolve_api_key()
        params = {"key": self.api_key}
        params.update(extra)
        return params

    async def _get_json(self, path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        async with httpx.AsyncClient(**self.client_args) as client:
            try:
                resp = await client.get(url, params=self._params(params), headers=self.headers)
            except httpx.RequestError as e:
                logger.error(f"Shodan 请求异常: {e}")
                raise ShodanAPIError(f"Shodan 请求异常: {e}") from e

        if resp.status_code in (401, 403):
            raise ShodanAPIError("Shodan 认证失败或权限不足，请检查 API Key。")
        if resp.status_code == 429:
            raise ShodanAPIError("Shodan 触发频率或额度限制，请稍后重试或降低 --shodan-limit。")
        if resp.status_code >= 400:
            raise ShodanAPIError(f"Shodan HTTP 错误: {resp.status_code} {resp.text[:120]}")

        try:
            data = resp.json()
        except ValueError as e:
            raise ShodanAPIError("Shodan 返回非 JSON 响应。") from e

        if isinstance(data, dict) and data.get("error"):
            raise ShodanAPIError(f"Shodan 查询失败: {data.get('error')}")

        return data if isinstance(data, dict) else {}

    async def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """搜索 Shodan 资产，按 limit 截断结果。"""
        query = (query or "").strip()
        if not query:
            raise ShodanAPIError("Shodan 查询语句不能为空。")

        safe_limit = max(1, int(limit or 100))
        pages = max(1, math.ceil(safe_limit / self.PAGE_SIZE))
        results: List[Dict[str, Any]] = []
        self.last_total = 0

        for page in range(1, pages + 1):
            logger.info(f"正在查询 Shodan 第 {page} 页... Query: [{query}]")
            data = await self._get_json(
                "/shodan/host/search",
                {
                    "query": query,
                    "page": page,
                    "minify": "true",
                }
            )
            self.last_total = int(data.get("total", self.last_total) or 0)
            matches = data.get("matches", [])
            if not matches:
                break

            results.extend([m for m in matches if isinstance(m, dict)])
            if len(results) >= safe_limit:
                break

        return results[:safe_limit]

    async def host_search(self, ip: str) -> Dict[str, Any]:
        """查询单 IP 的 Shodan Host 画像。"""
        ip = (ip or "").strip()
        if not ip:
            raise ShodanAPIError("Shodan Host 查询目标不能为空。")

        logger.info(f"正在查询 Shodan Host 画像: {ip}")
        return await self._get_json(f"/shodan/host/{ip}", {"minify": "false"})
