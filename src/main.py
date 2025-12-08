import argparse
import json
from rich.console import Console
from rich.panel import Panel

from parsers import get_parser
from utils.log_loader import load_log_lines
from utils.ioc_extractor import extract_iocs
from mitre.mapper import map_event_to_mitre
from llm_engine.mock_llm import generate_explanation

console = Console()


def pretty_print_event(idx, event, iocs, mitre_techniques, explanation):
    header = f"Event #{idx}"
    lines = [
        f"Timestamp   : {event.get('timestamp')}",
        f"Source IP   : {event.get('source_ip')}",
        f"Destination : {event.get('destination_ip')}",
        f"Action      : {event.get('action')}",
        f"Category    : {event.get('category')}",
        f"Severity    : {event.get('severity')}",
        "",
        "Indicators:",
    ]

    if not iocs:
        lines.append("  (none)")
    else:
        for kind, values in iocs.items():
            for v in values:
                lines.append(f"  - {kind}: {v}")

    lines.append("")
    lines.append("MITRE ATT&CK:")
    if not mitre_techniques:
        lines.append("  (no techniques matched)")
    else:
        for t in mitre_techniques:
            lines.append(f"  - {t['id']} ({t['name']}) [{t.get('reason', 'heuristic')}]")

    lines.append("")
    lines.append("Explanation:")
    lines.append(f"  {explanation}")

    console.print(
        Panel("\n".join(lines), title=header, expand=False, border_style="cyan")
    )


def main():
    parser = argparse.ArgumentParser(description="AI Log Explainer")
    parser.add_argument("--file", required=True, help="Path to the log file")
    parser.add_argument("--parser", required=True, help="Parser to use (fortisiem, f5_waf, trendmicro)")
    parser.add_argument("--json", action="store_true", help="JSON output mode")

    args = parser.parse_args()

    vendor_parser = get_parser(args.parser)
    lines = load_log_lines(args.file)

    results = []

    for idx, line in enumerate(lines, start=1):
        event = vendor_parser.parse(line)

        if not event:
            continue  # skip unparsed lines

        iocs = extract_iocs(event["raw"])
        mitre_techniques = map_event_to_mitre(event, iocs)
        explanation = generate_explanation(event, mitre_techniques, iocs)

        record = {
            "event_index": idx,
            "event": event,
            "iocs": iocs,
            "mitre": mitre_techniques,
            "explanation": explanation,
        }
        results.append(record)

        if not args.json:
            pretty_print_event(idx, event, iocs, mitre_techniques, explanation)

    if args.json:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
