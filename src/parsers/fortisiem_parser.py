import re
from .base_parser import BaseParser

class FortiSIEMParser(BaseParser):
    """
    Parser for Palo Alto THREAT logs forwarded into FortiSIEM.
    Your sample logs follow the structure:
    
    <syslog header> 1,<timestamp>,<session>,THREAT,<subtype>,<id>,<timestamp>,
    <src_ip>,<dst_ip>,<natsrc>,<natdst>,<rule>,,,<threat>,<vsys>,<src_zone>,
    <dst_zone>,<src_intf>,<dst_intf>,<profile>,<ts>,<session_id>,<repeat>,
    <src_port>,<dst_port>,<natsrc_port>,<natdst_port>,<flags>,<proto>,
    <action>,,<category>,any,informational,<direction>,<misc>,...
    """

    def parse(self, line: str):
        if not line or "," not in line:
            return None

        # ------------------------------------------------------------
        # 1. Extract timestamp (Palo Alto THREAT format)
        # ------------------------------------------------------------
        timestamp_match = re.search(r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}", line)
        timestamp = timestamp_match.group(0) if timestamp_match else None

        # Split by comma (primary Palo Alto separators)
        parts = [p.strip() for p in line.split(",")]

        if len(parts) < 10:
            return None

        # ------------------------------------------------------------
        # 2. Extract source/destination IPs
        #    Based on your sample log positions:
        #    index 7 = source
        #    index 8 = destination
        # ------------------------------------------------------------
        try:
            src_ip = parts[7]
            dst_ip = parts[8]
        except Exception:
            src_ip = None
            dst_ip = None

        # ------------------------------------------------------------
        # 3. Extract correct "Category" field
        #    Your format shows:
        #
        #       alert,,Non-RFC Compliant NTP Traffic on Port 123(56473),any
        #
        #    So category is *between*:
        #       alert,,   and   ,any
        # ------------------------------------------------------------
        category_match = re.search(r"alert,,(.*?),any", line)
        if category_match:
            category = category_match.group(1).strip()
        else:
            # Fallback: trust last meaningful fields
            non_empty = [p for p in parts if p.strip()]
            category = non_empty[-3] if len(non_empty) >= 3 else "Unknown"

        # ------------------------------------------------------------
        # 4. Normalize severity/action
        # ------------------------------------------------------------
        action_match = re.search(r",(alert|deny|allow|drop),", line)
        action = action_match.group(1) if action_match else "alert"

        # Severity appears near end ("informational", "low", "medium", "high")
        severity_match = re.search(r",(informational|low|medium|high),", line, re.IGNORECASE)
        severity = severity_match.group(1).lower() if severity_match else "informational"

        # ------------------------------------------------------------
        # 5. Assemble normalized event
        # ------------------------------------------------------------
        return {
            "raw": line,
            "timestamp": timestamp,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "category": category,
            "action": action,
            "severity": severity,
            "metadata": {
                "vendor": "FortiSIEM (Palo Alto Forwarded)",
                "field_count": len(parts)
            }
        }
