import datetime
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from colorama import Fore, Style
from prettytable import PrettyTable

from config import settings
from core.ai import DeepSeekHandler
from core.excel import ExcelExporter
from core.scanner import NucleiScanner
from core.shodan_client import ShodanAPIError, ShodanClient, ShodanConfigError
from utils.logger import logger
from utils.printer import ResultPrinter, print_header, print_item


class ShodanHandler:
    """Shodan 业务层：归一化、展示、导出、报告和可选扫描。"""

    ASSET_FIELDS = [
        "engine", "host", "ip", "port", "protocol", "title", "domain",
        "country", "city", "org", "product", "version", "os", "timestamp"
    ]
    ASSET_FIELDS_STR = ",".join(ASSET_FIELDS)

    def __init__(self, client: Optional[ShodanClient] = None, enable_ai: bool = True):
        self.client = client or ShodanClient()
        self.exporter = ExcelExporter()
        self.ai_handler = DeepSeekHandler() if enable_ai else None
        self.scanner = None
        self.timestamp_suffix = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.project_dir: Optional[Path] = None

    def _build_default_base_name(self, prefix: str, raw: str) -> str:
        safe = re.sub(r"[^\w\-]", "_", raw or prefix).strip("_")[:40]
        return f"{prefix}_{safe or 'task'}"

    def _detect_export_format(self, export_format=None, outfile=None):
        if export_format:
            fmt = str(export_format).lower().strip(".")
        elif outfile and Path(outfile).suffix.lower() in [".xlsx", ".csv"]:
            fmt = Path(outfile).suffix.lower().lstrip(".")
        else:
            fmt = str(getattr(settings.system, "export_format", "xlsx")).lower().strip(".")
        return fmt if fmt in ["xlsx", "csv"] else "xlsx"

    def _resolve_output_context(self, base_name: str, outfile=None, outdir=None, export_format=None):
        requested_path = Path(outfile).expanduser() if outfile else None
        requested_name = requested_path.name if requested_path else None
        export_format = self._detect_export_format(export_format=export_format, outfile=outfile)

        if requested_path and requested_path.stem:
            base_name = requested_path.stem

        default_root = Path(getattr(settings.system, "output_dir", "results")).expanduser()
        if outdir:
            project_dir = Path(outdir).expanduser()
        elif requested_path and requested_path.parent != Path("."):
            project_dir = requested_path.parent
        else:
            project_dir = default_root / f"{base_name}_{self.timestamp_suffix}"

        project_dir.mkdir(parents=True, exist_ok=True)
        return project_dir, export_format, requested_name

    def _build_export_path(self, fallback_name, export_format, requested_name=None):
        filename = requested_name if requested_name else fallback_name
        return self.project_dir / Path(filename).with_suffix(f".{export_format}").name

    @staticmethod
    def _first_list_value(value: Any) -> str:
        if isinstance(value, list):
            clean = [str(v).strip() for v in value if str(v).strip()]
            return ", ".join(clean[:3])
        return str(value or "").strip()

    @staticmethod
    def _location_value(record: Dict[str, Any], key: str, fallback: str = "") -> str:
        location = record.get("location") if isinstance(record.get("location"), dict) else {}
        return str(location.get(key) or record.get(key) or fallback or "").strip()

    @staticmethod
    def _http_title(record: Dict[str, Any]) -> str:
        http_info = record.get("http") if isinstance(record.get("http"), dict) else {}
        return str(http_info.get("title") or record.get("title") or "").strip()

    @classmethod
    def _infer_scheme(cls, record: Dict[str, Any]) -> Tuple[Optional[str], str]:
        port = str(record.get("port") or "").strip()
        transport = str(record.get("transport") or record.get("_shodan", {}).get("module") or "tcp").lower()
        has_ssl = bool(record.get("ssl"))
        has_http = isinstance(record.get("http"), dict) and bool(record.get("http"))

        if has_ssl or port in {"443", "8443"}:
            return "https", "https"
        if has_http or port in {"80", "8080", "8000", "8888", "8081"}:
            return "http", "http"
        return None, transport

    @classmethod
    def _build_host(cls, record: Dict[str, Any]) -> str:
        ip = str(record.get("ip_str") or record.get("ip") or "").strip()
        port = str(record.get("port") or "").strip()
        if not ip:
            return ""

        scheme, _ = cls._infer_scheme(record)
        if not scheme:
            return f"{ip}:{port}" if port else ip

        default_port = "443" if scheme == "https" else "80"
        suffix = "" if port == default_port or not port else f":{port}"
        return f"{scheme}://{ip}{suffix}"

    @classmethod
    def normalize_record(cls, record: Dict[str, Any]) -> List[str]:
        """将 Shodan service/banner 归一化为统一资产字段行。"""
        if not isinstance(record, dict):
            record = {}

        _, protocol = cls._infer_scheme(record)
        domains = cls._first_list_value(record.get("hostnames") or record.get("domains"))

        return [
            "shodan",
            cls._build_host(record),
            str(record.get("ip_str") or record.get("ip") or "").strip(),
            str(record.get("port") or "").strip(),
            protocol,
            cls._http_title(record),
            domains,
            cls._location_value(record, "country_name", record.get("country_name", "")),
            cls._location_value(record, "city", record.get("city", "")),
            str(record.get("org") or record.get("isp") or "").strip(),
            str(record.get("product") or "").strip(),
            str(record.get("version") or "").strip(),
            str(record.get("os") or "").strip(),
            str(record.get("timestamp") or "").strip(),
        ]

    @classmethod
    def normalize_records(cls, records: Iterable[Dict[str, Any]]) -> List[List[str]]:
        return [cls.normalize_record(item) for item in records if isinstance(item, dict)]

    @staticmethod
    def collect_vulns(host_data: Dict[str, Any], limit: int = 12) -> List[str]:
        """收集 Shodan Host 返回的 CVE 摘要，只用于情报提示。"""
        vulns = set()

        def add_from(value):
            if isinstance(value, dict):
                for key in value.keys():
                    if str(key).upper().startswith("CVE-"):
                        vulns.add(str(key).upper())
            elif isinstance(value, list):
                for item in value:
                    if str(item).upper().startswith("CVE-"):
                        vulns.add(str(item).upper())

        add_from(host_data.get("vulns"))
        for service in host_data.get("data", []) or []:
            if isinstance(service, dict):
                add_from(service.get("vulns"))

        return sorted(vulns)[:limit]

    @staticmethod
    def format_search_markdown(query: str, rows: List[List[str]], max_rows: int = 25) -> str:
        if not rows:
            return f"🔍 Shodan 未发现资产: `{query}`"

        display_headers = ["Host", "IP", "Port", "Protocol", "Title", "Org", "Country", "Product"]
        display_indices = [1, 2, 3, 4, 5, 9, 7, 10]

        def clean(cell):
            s = str(cell).replace("|", "\\|").replace("\n", " ").strip()
            return (s[:47] + "...") if len(s) > 50 else s

        md = f"### 🔍 Shodan 检索结果: `{query}`\n\n"
        md += "| " + " | ".join(display_headers) + " |\n"
        md += "| " + " | ".join(["---"] * len(display_headers)) + " |\n"
        for row in rows[:max_rows]:
            md += "| " + " | ".join(clean(row[i] if i < len(row) else "") for i in display_indices) + " |\n"
        if len(rows) > max_rows:
            md += f"\n> *ℹ️ 共 {len(rows)} 条，仅显示前 {max_rows} 条*"
        return md

    @classmethod
    def format_host_markdown(cls, host_data: Dict[str, Any], ip: str) -> str:
        if not host_data:
            return f"❌ Shodan Host 画像为空: `{ip}`"

        vulns = cls.collect_vulns(host_data)
        res = [
            f"### 🖥️ Shodan Host 画像: `{host_data.get('ip_str') or ip}`",
            f"- **组织/ISP**: {host_data.get('org', '-') or '-'} / {host_data.get('isp', '-') or '-'}",
            f"- **ASN**: {host_data.get('asn', '-') or '-'}",
            f"- **位置**: {host_data.get('country_name', '-') or '-'} / {host_data.get('city', '-') or '-'}",
            f"- **开放端口**: {', '.join(str(p) for p in host_data.get('ports', [])[:30]) or '-'}",
        ]
        if vulns:
            res.append("- **CVE 摘要**: " + ", ".join(vulns) + "（来自 Shodan 情报，未本地验证）")

        rows = []
        for service in host_data.get("data", [])[:25]:
            if not isinstance(service, dict):
                continue
            title = cls._http_title(service)
            rows.append([
                service.get("port", "-"),
                service.get("transport", "-"),
                service.get("product", "-") or "-",
                service.get("version", "-") or "-",
                title or "-",
                service.get("timestamp", "-") or "-",
            ])

        if rows:
            res.append("\n| Port | Transport | Product | Version | Title | Timestamp |")
            res.append("| --- | --- | --- | --- | --- | --- |")
            for row in rows:
                res.append("| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in row) + " |")
        return "\n".join(res)

    async def run_search_task(self, query: str, limit: int = None, outfile=None, outdir=None,
                              export_format=None, ai_query: str = None, nuclei: bool = False,
                              scan_args: str = "") -> List[List[str]]:
        """执行 Shodan 搜索、展示、导出、AI 报告和可选扫描。"""
        limit = int(limit or getattr(settings.shodan, "default_limit", 100) or 100)
        base_name = self._build_default_base_name("shodan_search", query)
        self.project_dir, export_format, requested_name = self._resolve_output_context(
            base_name=base_name,
            outfile=outfile,
            outdir=outdir,
            export_format=export_format
        )

        logger.info(f"Shodan 项目目录: {self.project_dir}")
        logger.info(f"Shodan 导出格式: {export_format.upper()}")
        logger.info(f"Shodan 查询数量上限: {limit}")

        try:
            raw_results = await self.client.search(query, limit=limit)
        except (ShodanConfigError, ShodanAPIError) as e:
            logger.error(str(e))
            return []

        rows = self.normalize_records(raw_results)
        if not rows:
            logger.warning(f"Shodan 查询无数据: {query}")
            logger.warning("建议确认 Shodan 查询语法，或放宽 product/country/org 等条件。")
            return []

        print_header(f"Shodan 查询结果: {query} (共 {len(rows)} 条)")
        ResultPrinter.print_fofa_data(rows, self.ASSET_FIELDS_STR, is_ai_mode=bool(ai_query))

        export_path = self._build_export_path(
            fallback_name=f"shodan_asset_all_{self.timestamp_suffix}.{export_format}",
            export_format=export_format,
            requested_name=requested_name
        )
        self.exporter.save(
            rows,
            filename=str(export_path),
            fields=self.ASSET_FIELDS,
            export_format=export_format
        )

        if ai_query and self.ai_handler and self.ai_handler.client:
            report_path = self.project_dir / f"shodan_asset_report_{self.timestamp_suffix}.md"
            await self.ai_handler.generate_shodan_asset_report(rows, query, ai_query, str(report_path))

        if nuclei:
            scan_targets = sorted({row[1] for row in rows if len(row) > 1 and str(row[1]).startswith(("http://", "https://"))})
            if not scan_targets:
                logger.warning("Shodan 结果中没有可供 Nuclei 扫描的 HTTP(S) 目标，跳过扫描。")
            else:
                self.scanner = self.scanner or NucleiScanner()
                scan_file = await self.scanner.run_scan(
                    scan_targets,
                    project_dir=self.project_dir,
                    custom_args=scan_args,
                    filename_suffix=self.timestamp_suffix
                )
                if ai_query and scan_file and self.ai_handler and self.ai_handler.client:
                    report_path = self.project_dir / f"shodan_vuln_report_{self.timestamp_suffix}.md"
                    await self.ai_handler.generate_vuln_report(rows, scan_file, str(report_path), data_source="Shodan")

        return rows

    async def handle_host_query(self, ip: str, user_intent: str = None, outdir=None) -> Dict[str, Any]:
        """执行 Shodan 单 IP 画像并生成可选 AI 报告。"""
        try:
            host_data = await self.client.host_search(ip)
        except (ShodanConfigError, ShodanAPIError) as e:
            logger.error(str(e))
            return {}

        if not host_data:
            logger.error(f"Shodan 未查询到 Host: {ip}")
            return {}

        print_header(f"Shodan Host 深度画像: {host_data.get('ip_str', ip)}")
        print_item("IP地址", host_data.get("ip_str", ip))
        print_item("组织", host_data.get("org", "N/A"))
        print_item("ISP", host_data.get("isp", "N/A"))
        print_item("ASN", host_data.get("asn", "N/A"))
        print_item("国家/城市", f"{host_data.get('country_name', 'N/A')} / {host_data.get('city', 'N/A')}")

        vulns = self.collect_vulns(host_data)
        if vulns:
            print_item("CVE 摘要", ", ".join(vulns) + "（来自 Shodan 情报，未本地验证）")

        print(f"\n{Fore.CYAN}[*] Shodan 开放端口与服务详情:{Style.RESET_ALL}")
        table = PrettyTable(["Id", "Port", "Transport", "Product", "Version", "Title", "Timestamp"])
        table.align = "c"
        table.align["Title"] = "l"
        table.padding_width = 1
        table.header_style = "title"
        table.border = False

        services = [s for s in host_data.get("data", []) if isinstance(s, dict)]
        services.sort(key=lambda x: int(x.get("port") or 0))
        for idx, service in enumerate(services, start=1):
            port_val = service.get("port")
            port_display = f"{Fore.RED}{port_val}{Style.RESET_ALL}" if port_val in [22, 3389, 445, 1433, 6379, 7001] else port_val
            table.add_row([
                idx,
                port_display,
                service.get("transport", ""),
                service.get("product", "") or "",
                service.get("version", "") or "",
                self._http_title(service)[:40],
                str(service.get("timestamp", "")).split("T")[0],
            ])
        print(Fore.GREEN + str(table) + Style.RESET_ALL)

        if self.ai_handler and self.ai_handler.client:
            default_root = Path(getattr(settings.system, "output_dir", "results")).expanduser()
            report_dir = Path(outdir).expanduser() if outdir else default_root / f"shodan_host_{ip.replace('.', '_')}_{self.timestamp_suffix}"
            report_dir.mkdir(parents=True, exist_ok=True)
            report_path = report_dir / f"shodan_host_report_{ip}.md"
            report_content = await self.ai_handler.analyze_shodan_host_risk(host_data, user_intent=user_intent)
            if report_content:
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write(report_content)
                logger.info(f"Shodan Host 风险评估报告已保存: {report_path}")

        return host_data
