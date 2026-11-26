"""Scan all 15 decompiled APKs against expanded Synthient network hosts, SDK IDs, and xcpe-guard compound rules."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.adb_helpers import WORKSPACE_ROOT, save_json_evidence

sys.path.insert(0, str(WORKSPACE_ROOT / "scripts" / "02_packages_and_hashes"))
from audit_synthient_gap_checks import parse_synthient_observables

DECOMPILED_DIR: Path = WORKSPACE_ROOT / "decompiled"
TARGET_EXTENSIONS: frozenset[str] = frozenset({".java", ".xml", ".kt", ".txt", ".properties", ".json"})
EXTRA_BEHAVIORAL_TERMS: tuple[str, ...] = (
    "accessibilitykeydetector",
    "persist.networkstack",
    "com.android.system.ntp",
    "com.gaganode",
    "com.android.init.android",
    "dt-dev-ota-server",
    "uota.club",
    "uota.xyz",
    "allcloud9.com",
    "titannet.io",
)


def main() -> None:
    """Scan all decompiled APK folders for Synthient network hosts, SDK IDs, and compound behavioral indicators."""
    synthient = parse_synthient_observables()
    hosts: list[str] = synthient["network_hosts"]
    sdk_ids: list[str] = [entry["identifier"].lower() for entry in synthient["sdk_identifiers"]]
    behavioral = list(EXTRA_BEHAVIORAL_TERMS)

    results: dict[str, Any] = {}
    for apk_dir in sorted(DECOMPILED_DIR.iterdir()):
        if not apk_dir.is_dir():
            continue
        host_hits: dict[str, list[str]] = {}
        sdk_hits: dict[str, list[str]] = {}
        beh_hits: dict[str, list[str]] = {}
        scanned = 0

        for file_path in apk_dir.rglob("*"):
            if not file_path.is_file() or file_path.suffix.lower() not in TARGET_EXTENSIONS:
                continue
            scanned += 1
            try:
                content_lower = file_path.read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue

            rel_path: str | None = None
            for term in hosts:
                if term in content_lower:
                    if rel_path is None:
                        rel_path = str(file_path.relative_to(apk_dir))
                    host_hits.setdefault(term, []).append(rel_path)

            for term in sdk_ids:
                if term in content_lower:
                    if rel_path is None:
                        rel_path = str(file_path.relative_to(apk_dir))
                    sdk_hits.setdefault(term, []).append(rel_path)

            for term in behavioral:
                if term in content_lower:
                    if rel_path is None:
                        rel_path = str(file_path.relative_to(apk_dir))
                    beh_hits.setdefault(term, []).append(rel_path)

        results[apk_dir.name] = {
            "scanned_files": scanned,
            "synthient_host_hits": {k: sorted(v)[:20] for k, v in sorted(host_hits.items())},
            "sdk_id_hits": {k: sorted(v)[:20] for k, v in sorted(sdk_hits.items())},
            "compound_behavioral_hits": {k: sorted(v)[:20] for k, v in sorted(beh_hits.items())},
        }
        print(
            f"{apk_dir.name}: scanned={scanned}, hosts={list(host_hits.keys())}, "
            f"sdk_ids={list(sdk_hits.keys())}, beh={list(beh_hits.keys())}",
            flush=True,
        )

    save_json_evidence("04_extraction_and_decompile/synthient_decompiled_scan.json", results)


if __name__ == "__main__":
    main()
