import json
from pathlib import Path


OUTPUT_ROOT = Path(__file__).resolve().parent.parent
SESSIONS_DIR = OUTPUT_ROOT / "sessions"
ARTIFACTS_DIR = OUTPUT_ROOT / "artifacts"
REPORTS_DIR = OUTPUT_ROOT / "reports"


def _build_path(state):
    started_at = state["started_at"].replace(":", "-")
    return SESSIONS_DIR / f"{started_at}.json"


def display_output_path(path):
    return f"{path.parent.name}/{path.name}"


def save_state_snapshot(state, path=None):
    path = Path(path) if path else _build_path(state)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return path


def prune_empty_output_dirs():
    for path in (ARTIFACTS_DIR, REPORTS_DIR, SESSIONS_DIR):
        try:
            path.rmdir()
        except OSError:
            pass
