"""Scan all decompiled APK source trees against Google Threat Intelligence XCPE/affiliate IOCs and sensitive APIs."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.adb_helpers import WORKSPACE_ROOT, save_json_evidence

DECOMPILED_DIR: Path = WORKSPACE_ROOT / "decompiled"
SAMPLES_DIR: Path = WORKSPACE_ROOT / "samples_from_google_cloud_threat_intelligence"
TARGET_EXTENSIONS: frozenset[str] = frozenset({".java", ".xml", ".kt", ".txt", ".properties", ".json"})

BEHAVIORAL_KEYWORDS: tuple[str, ...] = (
    "com.oemservice",
    "com.abc.nexus",
    "com.vs.grass",
    "com.newtv.cboxtv",
    "com.ota.service",
    "com.android.sso.auth.handler",
    "x.cpe",
    "persist.sys.cpe",
    "ro.mecool",
    "package_verifier_user_consent",
    "SurfaceControl",
    "sendKeyDownUpSync",
    "libtraceroute",
    "libseccomp_guard",
    "libfleetshare",
    "libexploit",
    "libnative_keys",
    "videostrong",
    "DexClassLoader",
    "InMemoryDexClassLoader",
    "org.eclipse.paho",
    "mqtt",
    "PackageInstaller",
)


def load_network_iocs() -> list[str]:
    """Parse network indicators from network_indicators.md into clean lowercase strings."""
    indicators: list[str] = []
    file_path = SAMPLES_DIR / "network_indicators.md"
    for line in file_path.read_text(encoding="utf-8").splitlines():
        if not line.strip().startswith("|") or "---" in line or "Indicator" in line:
            continue
        columns = [col.strip().replace("\u00a0", "") for col in line.strip().strip("|").split("|")]
        if not columns or not columns[0]:
            continue
        cleaned = columns[0].replace("[.]", ".").lstrip("*.").strip().lower()
        if cleaned:
            indicators.append(cleaned)
    return sorted(set(indicators))


def scan_apk_tree(apk_dir: Path, network_iocs: list[str], behavioral_terms: list[str]) -> dict[str, Any]:
    """Scan all text/source files in one decompiled APK folder using fast lowercase substring matching."""
    network_hits: dict[str, list[str]] = {}
    behavioral_hits: dict[str, list[str]] = {}

    scanned_files = 0
    for file_path in apk_dir.rglob("*"):
        if not file_path.is_file() or file_path.suffix.lower() not in TARGET_EXTENSIONS:
            continue
        scanned_files += 1
        try:
            content_lower = file_path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue

        rel_path: str | None = None
        for term in network_iocs:
            if term in content_lower:
                if rel_path is None:
                    rel_path = str(file_path.relative_to(apk_dir))
                network_hits.setdefault(term, []).append(rel_path)

        for term in behavioral_terms:
            if term in content_lower:
                if rel_path is None:
                    rel_path = str(file_path.relative_to(apk_dir))
                behavioral_hits.setdefault(term, []).append(rel_path)

    return {
        "scanned_files": scanned_files,
        "network_ioc_hits": {k: sorted(v)[:20] for k, v in sorted(network_hits.items())},
        "behavioral_hits": {k: sorted(v)[:20] for k, v in sorted(behavioral_hits.items())},
    }


def main() -> None:
    """Run static IOC scan across all decompiled directories and save JSON evidence."""
    network_iocs = load_network_iocs()
    behavioral_terms = [term.lower() for term in BEHAVIORAL_KEYWORDS]
    results: dict[str, Any] = {}
    for apk_dir in sorted(DECOMPILED_DIR.iterdir()):
        if not apk_dir.is_dir():
            continue
        results[apk_dir.name] = scan_apk_tree(apk_dir, network_iocs, behavioral_terms)
        net_count = len(results[apk_dir.name]["network_ioc_hits"])
        beh_keys = list(results[apk_dir.name]["behavioral_hits"].keys())
        print(f"{apk_dir.name}: scanned={results[apk_dir.name]['scanned_files']} files, net_iocs={net_count}, behavioral={beh_keys}", flush=True)

    save_json_evidence("04_extraction_and_decompile/static_ioc_scan.json", results)


if __name__ == "__main__":
    main()
