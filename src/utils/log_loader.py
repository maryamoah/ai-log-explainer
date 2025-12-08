from typing import List

def load_log_lines(path: str) -> List[str]:
    """
    Loads a log file and returns a list of non-empty lines.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.rstrip("\n") for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}")
        return []
