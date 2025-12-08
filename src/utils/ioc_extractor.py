import re
from typing import Dict, List

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9-]+\.)+(com|net|org|edu|gov|om|gh|de|fi)\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")

def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Extract common indicators of compromise (IOCs) from a log string.
    """
    ips = sorted(set(IPV4_RE.findall(text)))
    emails = sorted(set(EMAIL_RE.findall(text)))
    domains = sorted(set([d[0] + d[1] for d in DOMAIN_RE.findall(text)]))
    hashes = sorted(set(HASH_RE.findall(text)))

    result: Dict[str, List[str]] = {}
    if ips:
        result["ip"] = ips
    if emails:
        result["email"] = emails
    if domains:
        result["domain"] = domains
    if hashes:
        result["hash"] = hashes

    return result
