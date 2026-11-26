"""Gap-closure audit against Synthient 'Internals of a Badbox Operation' and xcpe-guard compound IOCs."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.adb_helpers import EVIDENCE_DIR, WORKSPACE_ROOT, connect_target_device, run_shell_checked, save_json_evidence

GITHUB_RESOURCES_DIR: Path = WORKSPACE_ROOT / "github-resources"
SHA256_RE: re.Pattern[str] = re.compile(r"\b[a-fA-F0-9]{64}\b")

COMPOUND_MALICIOUS_PACKAGES: tuple[str, ...] = (
    "x.cpe",
    "com.abc.nexus",
    "com.vs.grass",
    "com.android.system.ntp",
    "com.android.sso.auth.handler",
    "com.newtv.cboxtv",
    "com.ota.service",
    "com.android.init.android",
)

NATIVE_ARTIFACT_NAMES: tuple[str, ...] = (
    "airship",
    "grass_android_2.0",
    "lw_android_agent",
    "videoadtime_pproxy",
    "libjaguar.so",
    "libseccomp_guard.so",
    "libfleetshare.so",
    "libexploit.so",
    "libnative_keys.so",
    "nat-checker",
    "frp-lite.jar",
    "ol_imp_30737.jar",
    "backup_7.jar",
    "static_host_20260206.jar",
)


def parse_synthient_observables() -> dict[str, Any]:
    """Extract SHA256 hashes, cert fingerprints, SDK IDs, and network observables from Synthient markdown."""
    md_path = GITHUB_RESOURCES_DIR / "synthient_public_research.md"
    lines = md_path.read_text(encoding="utf-8").splitlines()

    file_hashes: dict[str, dict[str, str]] = {}
    cert_fingerprints: dict[str, str] = {}
    network_indicators: list[str] = []
    sdk_identifiers: list[dict[str, str]] = []

    section = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## "):
            section = stripped.removeprefix("## ").strip()
            continue
        if not stripped.startswith("|") or "---" in stripped:
            continue
        cols = [c.strip() for c in stripped.strip("|").split("|")]
        if section == "File Observables" and len(cols) >= 5 and SHA256_RE.fullmatch(cols[3]):
            file_hashes[cols[3].lower()] = {
                "filename": cols[0],
                "version": cols[1],
                "first_seen": cols[2],
                "description": cols[4],
            }
        elif section == "Certificate Fingerprints" and len(cols) >= 4 and SHA256_RE.fullmatch(cols[2]):
            cert_fingerprints[cols[2].lower()] = f"{cols[0]} ({cols[3]})"
        elif section == "Network Observables" and len(cols) >= 4 and cols[0] != "Artifact / Component":
            cleaned = cols[2].replace("[.]", ".").strip()
            for prefix in ("hxxps://", "hxxp://"):
                if cleaned.lower().startswith(prefix):
                    cleaned = cleaned[len(prefix) :]
            host_part = cleaned.split("/", maxsplit=1)[0].split(":", maxsplit=1)[0]
            host_part = host_part.replace("{ver}{model}.", "").strip().lower()
            if host_part:
                network_indicators.append(host_part)
        elif section == "SDK Identifiers" and len(cols) >= 2 and cols[0] != "SDK":
            sdk_identifiers.append({"sdk": cols[0], "identifier": cols[1]})

    return {
        "file_hashes": file_hashes,
        "cert_fingerprints": cert_fingerprints,
        "network_hosts": sorted(set(network_indicators)),
        "sdk_identifiers": sdk_identifiers,
    }


def check_existing_apk_hashes(synthient_hashes: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    """Cross-check all 143 previously collected APK SHA256 hashes against Synthient file observables."""
    audit_path = EVIDENCE_DIR / "02_packages_and_hashes" / "package_ioc_audit.json"
    all_packages = json.loads(audit_path.read_text(encoding="utf-8"))["data"]["all_packages"]
    matches: list[dict[str, Any]] = []
    for pkg in all_packages:
        digest = (pkg.get("sha256") or "").lower()
        if digest in synthient_hashes:
            matches.append({
                "package": pkg["package"],
                "apk_path": pkg["apk_path"],
                "uid": pkg["uid"],
                "sha256": digest,
                "synthient_entry": synthient_hashes[digest],
            })
    return matches


def check_existing_properties() -> dict[str, str]:
    """Check collected device properties for persist.networkstack.*, cpe, and Videostrong/Yoka/UOTA hints."""
    profile_path = EVIDENCE_DIR / "01_recon" / "device_profile.json"
    all_props = json.loads(profile_path.read_text(encoding="utf-8"))["data"]["all_properties"]
    keywords = ("networkstack", "cpe", "uota", "yoka", "titannet", "airship", "grass", "gaganode", "allcloud", "s-itv", "szbboys", "anyev", "mecool", "videostrong")
    return {
        k: v
        for k, v in sorted(all_props.items())
        if any(kw in k.lower() or kw in v.lower() for kw in keywords)
    }


def run_live_compound_checks() -> dict[str, Any]:
    """Query live device for accessibility hooks, Private DNS, native binaries, and APK certs."""
    device = connect_target_device()
    find_patterns = " -o ".join(f"-name '*{name}*'" for name in NATIVE_ARTIFACT_NAMES)
    commands: dict[str, str] = {
        "enabled_accessibility_services": "settings get secure enabled_accessibility_services",
        "accessibility_enabled": "settings get secure accessibility_enabled",
        "dumpsys_accessibility": "dumpsys accessibility 2>&1",
        "private_dns_mode": "settings get global private_dns_mode",
        "private_dns_specifier": "settings get global private_dns_specifier",
        "package_verifier_user_consent": "settings get global package_verifier_user_consent",
        "native_artifact_scan": f"find /system /vendor /product /system_ext /oem /data/local/tmp -maxdepth 5 \\( {find_patterns} \\) 2>/dev/null",
        "gaganode_package_check": "pm list packages | grep -iE 'gaganode|nexus|grass|cboxtv|ntp|sso\\.auth|oemservice|x\\.cpe|init\\.android|ota\\.service'",
        "oemservice_size": "stat -c '%n %s' /system/priv-app/app_xcpe_preset/app_xcpe_preset.apk 2>&1",
        "sdcard_download_hashes": "sha256sum /sdcard/Download/*.apk 2>&1",
    }
    return {label: run_shell_checked(device, cmd, timeout=30.0) for label, cmd in commands.items()}


def main() -> None:
    """Run all gap checks and persist structured evidence."""
    synthient = parse_synthient_observables()
    apk_hash_matches = check_existing_apk_hashes(synthient["file_hashes"])
    prop_hits = check_existing_properties()
    live_checks = run_live_compound_checks()

    report = {
        "synthient_counts": {
            "file_hashes": len(synthient["file_hashes"]),
            "cert_fingerprints": len(synthient["cert_fingerprints"]),
            "network_hosts": len(synthient["network_hosts"]),
            "sdk_identifiers": len(synthient["sdk_identifiers"]),
        },
        "apk_hash_matches": apk_hash_matches,
        "suspicious_property_hits": prop_hits,
        "live_compound_checks": live_checks,
    }
    out_path = save_json_evidence("02_packages_and_hashes/synthient_gap_audit.json", report)
    print(f"Saved Synthient gap audit to: {out_path}")
    print(f"Synthient observables loaded: {report['synthient_counts']}")
    print(f"APK SHA256 matches: {json.dumps(apk_hash_matches, indent=2)}")
    print(f"Suspicious property hits: {json.dumps(prop_hits, indent=2)}")
    for k, v in live_checks.items():
        print(f"=== {k} (rc={v['returncode']}) ===")
        print(v["output"][:1200])


if __name__ == "__main__":
    main()
