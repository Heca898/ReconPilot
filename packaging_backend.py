"""Minimal PEP 517 backend for offline, dependency-free wheel builds.

This keeps `pip install .` and editable installs working from a clean copy
without requiring setuptools or network access on the target system.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


PROJECT_NAME = "reconpilot"
PROJECT_VERSION = "1.0.0"
PROJECT_SUMMARY = "Deterministic reconnaissance and vulnerability-enrichment CLI"
PYTHON_REQUIRES = ">=3.10"
CONSOLE_SCRIPTS = {"reconpilot": "reconpilot.__main__:main"}

ROOT = Path(__file__).resolve().parent
PACKAGE_DIR = ROOT / "reconpilot"
DIST_INFO = f"{PROJECT_NAME}-{PROJECT_VERSION}.dist-info"


def _metadata_text() -> str:
    return (
        "Metadata-Version: 2.1\n"
        f"Name: {PROJECT_NAME}\n"
        f"Version: {PROJECT_VERSION}\n"
        f"Summary: {PROJECT_SUMMARY}\n"
        f"Requires-Python: {PYTHON_REQUIRES}\n"
    )


def _wheel_text() -> str:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: reconpilot-packaging-backend\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    )


def _entry_points_text() -> str:
    lines = ["[console_scripts]"]
    for name, target in CONSOLE_SCRIPTS.items():
        lines.append(f"{name} = {target}")
    lines.append("")
    return "\n".join(lines)


def _iter_package_files() -> list[Path]:
    files = []
    for path in PACKAGE_DIR.rglob("*"):
        if not path.is_file():
            continue
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        files.append(path)
    return sorted(files)


def _dist_info_dir(metadata_directory: str | os.PathLike[str]) -> Path:
    dist_info = Path(metadata_directory) / DIST_INFO
    dist_info.mkdir(parents=True, exist_ok=True)
    (dist_info / "METADATA").write_text(_metadata_text(), encoding="utf-8")
    (dist_info / "WHEEL").write_text(_wheel_text(), encoding="utf-8")
    (dist_info / "entry_points.txt").write_text(_entry_points_text(), encoding="utf-8")
    return dist_info


def _hash_bytes(data: bytes) -> tuple[str, str]:
    digest = hashlib.sha256(data).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"sha256={encoded}", str(len(data))


def _wheel_name() -> str:
    return f"{PROJECT_NAME}-{PROJECT_VERSION}-py3-none-any.whl"


def _write_record(rows: list[tuple[str, str, str]]) -> bytes:
    lines = []
    for row in rows:
        lines.append(",".join(row))
    return ("\n".join(lines) + "\n").encode("utf-8")


def get_requires_for_build_wheel(config_settings=None) -> list[str]:
    return []


def get_requires_for_build_editable(config_settings=None) -> list[str]:
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None) -> str:
    return _dist_info_dir(metadata_directory).name


def prepare_metadata_for_build_editable(metadata_directory, config_settings=None) -> str:
    return _dist_info_dir(metadata_directory).name


def _build_archive(wheel_directory: str | os.PathLike[str], editable: bool) -> str:
    wheel_directory = Path(wheel_directory)
    wheel_directory.mkdir(parents=True, exist_ok=True)
    wheel_path = wheel_directory / _wheel_name()
    record_rows: list[tuple[str, str, str]] = []

    with ZipFile(wheel_path, "w", compression=ZIP_DEFLATED) as archive:
        if editable:
            pth_name = f"{PROJECT_NAME}.pth"
            pth_bytes = f"{ROOT}\n".encode("utf-8")
            archive.writestr(pth_name, pth_bytes)
            record_rows.append((pth_name, *_hash_bytes(pth_bytes)))
        else:
            for file_path in _iter_package_files():
                relative = file_path.relative_to(ROOT).as_posix()
                data = file_path.read_bytes()
                archive.writestr(relative, data)
                record_rows.append((relative, *_hash_bytes(data)))

        metadata_files = {
            f"{DIST_INFO}/METADATA": _metadata_text().encode("utf-8"),
            f"{DIST_INFO}/WHEEL": _wheel_text().encode("utf-8"),
            f"{DIST_INFO}/entry_points.txt": _entry_points_text().encode("utf-8"),
        }
        for name, data in metadata_files.items():
            archive.writestr(name, data)
            record_rows.append((name, *_hash_bytes(data)))

        record_name = f"{DIST_INFO}/RECORD"
        record_rows.append((record_name, "", ""))
        record_bytes = _write_record(record_rows)
        archive.writestr(record_name, record_bytes)

    return wheel_path.name


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None) -> str:
    return _build_archive(wheel_directory, editable=False)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None) -> str:
    return _build_archive(wheel_directory, editable=True)
