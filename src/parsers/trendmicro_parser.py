from .base_parser import BaseParser
import re

class TrendMicroParser(BaseParser):
    """
    Simplified parser for Trend Micro Apex Central CEF logs.
    Extracts timestamp, source/destination IPs, category, action, severity.
    """

    def parse(self, line: str):
        if "Trend Micro" not in line:
            return None

        # Extract timestamp (rt=)
        rt_match = re.search(r"rt=(.*?)\s", line)
        timestamp = rt_match.group(1) if rt_match else ""

        # Extract key=value fields
        fields = dict(re.findall(r"(\w+)=([^\s]+)", line))

        src_ip = fields.get("src")
        dst_ip = fields.get("dst")
        category = fields.get("cat", "AV event")
        action = fields.get("act", "")
        severity = "high" if "Mal_" in line else "medium"

        return {
            "raw": line,
            "timestamp": timestamp,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "category": category,
            "action": action,
            "severity": severity,
            "metadata": {"vendor": "Trend Micro"},
        }
