"""Summarize package IOC audit and runtime evidence into readable console and markdown output."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.adb_helpers import EVIDENCE_DIR


def summarize_audit() -> None:
    """Print exact IOC matches, keyword matches, third-party apps, and non-Google system packages."""
    audit_path = EVIDENCE_DIR / "02_packages_and_hashes" / "package_ioc_audit.json"
    audit_data = json.loads(audit_path.read_text(encoding="utf-8"))["data"]

    print("=== EXACT IOC PACKAGE MATCHES ===")
    print(json.dumps(audit_data["package_name_matches"], indent=2))
    print("=== KEYWORD MATCHES ===")
    print(json.dumps(audit_data["keyword_matches"], indent=2))
    print("=== THIRD PARTY PACKAGES ===")
    print(json.dumps(audit_data["third_party_packages"], indent=2))
    print("=== BINARY SCAN ===")
    print(json.dumps(audit_data["binary_scan"], indent=2))
    print("=== DISABLED PACKAGES ===")
    print(audit_data["disabled_packages_raw"])
    print("=== NON-GOOGLE / NON-ANDROID SYSTEM PACKAGES ===")
    excluded_prefixes = ("com.android.", "com.google.", "com.realtek.")
    for pkg in audit_data["all_packages"]:
        name = pkg["package"]
        if pkg["is_third_party"]:
            continue
        if name == "android" or name.startswith(excluded_prefixes):
            continue
        print(f"{name} | uid={pkg['uid']} | {pkg['apk_path']} | {pkg['sha256']}")


if __name__ == "__main__":
    summarize_audit()
