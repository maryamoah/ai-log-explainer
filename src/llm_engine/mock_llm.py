from typing import Dict, Any, List

def generate_explanation(
    event: Dict[str, Any],
    mitre_techniques: List[Dict[str, str]],
    iocs: Dict[str, List[str]],
) -> str:
    """
    Generates a human-readable explanation of the event,
    mimicking the behaviour of an LLM without using external APIs.
    """

    src = event.get("source_ip", "unknown source")
    dst = event.get("destination_ip", "unknown destination")
    cat = event.get("category", "Uncategorised event")
    sev = event.get("severity", "unknown")
    action = event.get("action", "")

    # Build IOC text
    ioc_text = ""
    if iocs:
        parts = []
        for key, values in iocs.items():
            parts.append(f"{key}: {', '.join(values)}")
        ioc_text = " Observed indicators include " + "; ".join(parts) + "."

    # Build MITRE text
    mitre_text = ""
    if mitre_techniques:
        labels = [f"{t['id']} ({t['name']})" for t in mitre_techniques]
        mitre_text = (
            " The behaviour aligns with the following MITRE ATT&CK techniques: "
            + ", ".join(labels) + "."
        )

    explanation = (
        f"This log entry describes '{cat}' involving traffic from {src} to {dst}. "
        f"The event is recorded with '{sev}' severity and action '{action}'."
        f"{ioc_text}{mitre_text} This explanation is generated heuristically."
    )

    return explanation
