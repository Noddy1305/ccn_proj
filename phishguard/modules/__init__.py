from functools import lru_cache
from pathlib import Path

import yaml

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"


@lru_cache(maxsize=1)
def load_config():
    """Read config.yaml once. All weights and settings live there (NFR-5)."""
    return yaml.safe_load(CONFIG_PATH.read_text())


def status_for(findings, config):
    """One rule for every check card: fail if any heavy red flag, warn if any flag, else pass."""
    heavy = config.get("thresholds", {}).get("heavy_flag_points", 20)
    if any(f["points"] >= heavy for f in findings):
        return "fail"
    return "warn" if findings else "pass"
