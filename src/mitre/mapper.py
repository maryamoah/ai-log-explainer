from typing import Dict, Any, List

# Very small illustrative MITRE ATT&CK rule set
MITRE_RULES = [
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "keywords": ["sql injection", "sqli", "sql-injection", "remote code", "rce"],
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "keywords": ["cmd.exe", "powershell", "bash", "sh -c", "command injection"],
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "keywords": ["brute", "login failed", "authentication failure"],
    },
    {
        "id": "T1046",
        "name": "Network Service Scanning",
        "keywords": ["port scan", "nmap", "scan", "ntp-non-rfc"],
    },
    {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "keywords": ["http", "https", "dns", "ntp"],
    },
]


def map_event_to_mitre(event: Dict[str, Any], iocs: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Applies rule-based MITRE ATT&CK technique mapping.
    Matches keywords in category, action, or raw log text.
    """

    text = " ".join(
        str(event.get(k, "")).lower() for k in ("category", "action", "raw")
    )

    techniques: List[Dict[str, str]] = []

    # Keyword-based matching
    for rule in MITRE_RULES:
        if any(keyword in text for keyword in rule["keywords"]):
            techniques.append(
                {
                    "id": rule["id"],
                    "name": rule["name"],
                    "reason": "keyword match",
                }
            )

    # Heuristic for NTP-related scanning with external IPs
    if (
        "ntp" in text
        and "ip" in iocs
        and not any(t["id"] == "T1046" for t in techniques)
    ):
        techniques.append(
            {
                "id": "T1046",
                "name": "Network Service Scanning",
                "reason": "ntp-like behavior with external IPs",
            }
        )

    return techniques
