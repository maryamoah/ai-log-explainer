from .base_parser import BaseParser
import re

class F5WAFParser(BaseParser):
    """
    Simplified F5 WAF log parser.
    Extracts source IP, destination IP, signature, URI, timestamp.
    """

    def parse(self, line: str):
        if not line:
            return None

        # Extract key=value pairs
        data = {}
        for match in re.findall(r'(\w+)=(".*?"|\S+)', line):
            key, value = match
            data[key] = value.strip('"')

        # Parse values
        src_ip = data.get("src")
        dst_ip = data.get("dst")
        signature = data.get("sig", "WAF event")
        uri = data.get("uri", "")
        timestamp = data.get("time", "")

        return {
            "raw": line,
            "timestamp": timestamp,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "category": signature,
            "action": data.get("action", "blocked"),
            "severity": data.get("severity", "medium"),
            "metadata": {
                "vendor": "F5 WAF",
                "uri": uri,
            },
        }
