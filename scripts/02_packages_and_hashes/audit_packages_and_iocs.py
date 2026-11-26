"""Phase 2 script: enumerate installed packages, compute APK/ELF SHA256 hashes on-device, and match XCPE IOCs."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.adb_helpers import WORKSPACE_ROOT, connect_target_device, run_shell_checked, save_json_evidence

SAMPLES_DIR: Path = WORKSPACE_ROOT / "samples_from_google_cloud_threat_intelligence"
SHA256_PATTERN: re.Pattern[str] = re.compile(r"\b[a-fA-F0-9]{64}\b")
SUSPICIOUS_PACKAGE_KEYWORDS: tuple[str, ...] = (
    "xcpe",
    "x.cpe",
    "oemservice",
    "abc.nexus",
    "vs.grass",
    "cboxtv",
    "ota.service",
    "sso.auth",
    "videostrong",
    "mecool",
    "szbboys",
    "anyev",
    "linkfog",
    "appsalt",
    "honeygain",
    "gaganode",
    "traffmonetizer",
    "earnfm",
    "netnut",
    "moyu",
    "hiddenview",
    "yokatv",
    "amh",
)


def load_known_iocs() -> dict[str, Any]:
    """Load SHA256 hashes, package names, and network indicators from Google Threat Intelligence markdown files."""
    known_hashes: dict[str, dict[str, str]] = {}
    known_packages: set[str] = set()
    known_domains: list[str] = []

    for md_name in ("core_malware_samples.md", "affiliate_malware.md"):
        file_path = SAMPLES_DIR / md_name
        if not file_path.exists():
            continue
        for line in file_path.read_text(encoding="utf-8").splitlines():
            if not line.strip().startswith("|") or "---" in line or "Representative SHA256" in line:
                continue
            columns = [col.strip().replace("\u00a0", "") for col in line.strip().strip("|").split("|")]
            if len(columns) < 3:
                continue
            hash_match = SHA256_PATTERN.search(line)
            if hash_match:
                sha256_value = hash_match.group(0).lower()
                known_hashes[sha256_value] = {
                    "source_file": md_name,
                    "tool": columns[0],
                    "identifier": columns[1],
                    "notes": columns[3] if len(columns) > 3 else "",
                }
            if md_name == "core_malware_samples.md" and columns[1] and not columns[1].endswith(".so"):
                known_packages.add(columns[1])

    network_file = SAMPLES_DIR / "network_indicators.md"
    if network_file.exists():
        for line in network_file.read_text(encoding="utf-8").splitlines():
            if not line.strip().startswith("|") or "---" in line or "Indicator" in line:
                continue
            columns = [col.strip().replace("\u00a0", "") for col in line.strip().strip("|").split("|")]
            if not columns or not columns[0]:
                continue
            cleaned_indicator = columns[0].replace("[.]", ".")
            known_domains.append(cleaned_indicator)

    known_packages.update({
        "x.cpe",
        "com.oemservice",
        "com.abc.nexus",
        "com.vs.grass",
        "com.newtv.cboxtv",
        "com.ota.service",
        "com.android.sso.auth.handler",
    })

    return {
        "hashes": known_hashes,
        "packages": sorted(known_packages),
        "network_indicators": known_domains,
    }


def parse_pm_list_packages(raw_output: str) -> list[dict[str, str]]:
    """Parse 'pm list packages -f -U' output into structured package entries."""
    packages: list[dict[str, str]] = []
    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("package:"):
            continue
        body = stripped.removeprefix("package:")
        uid_part = ""
        if " uid:" in body:
            body, uid_part = body.rsplit(" uid:", maxsplit=1)
        if "=" not in body:
            continue
        apk_path, package_name = body.rsplit("=", maxsplit=1)
        packages.append({
            "package": package_name.strip(),
            "apk_path": apk_path.strip(),
            "uid": uid_part.strip(),
        })
    return packages


def compute_remote_sha256_map(device: Any, paths: list[str]) -> dict[str, str]:
    """Compute SHA256 hashes on-device for a list of APK or binary paths in batches."""
    hash_map: dict[str, str] = {}
    batch_size = 40
    for index in range(0, len(paths), batch_size):
        batch = paths[index : index + batch_size]
        quoted_paths = " ".join(f'"{p}"' for p in batch)
        command = f"sha256sum {quoted_paths} 2>/dev/null"
        result = run_shell_checked(device, command, timeout=60.0)
        for line in result["output"].splitlines():
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 2 and len(parts[0]) == 64:
                hash_map[parts[1].strip()] = parts[0].lower()
    return hash_map


def scan_suspicious_binaries(device: Any) -> dict[str, Any]:
    """Search common writable and OEM directories for suspicious binaries or scripts."""
    find_command = (
        "find /oem /data/local/tmp /vendor/bin /system/bin /system/xbin "
        "-maxdepth 4 \\( -name '*.apk' -o -name '*.so' -o -name '*.dex' -o -name '*cpe*' "
        "-o -name '*nexus*' -o -name '*seccomp*' -o -name '*traceroute*' -o -name '*fleetshare*' "
        "-o -name '*exploit*' -o -name '*native_keys*' \\) 2>/dev/null"
    )
    find_result = run_shell_checked(device, find_command, timeout=30.0)
    found_paths = [line.strip() for line in find_result["output"].splitlines() if line.strip()]
    hashes = compute_remote_sha256_map(device, found_paths) if found_paths else {}
    return {
        "paths": found_paths,
        "sha256": hashes,
    }


def run_package_and_ioc_audit() -> dict[str, Any]:
    """Enumerate all packages, third-party packages, disabled packages, hashes, and IOC matches."""
    device = connect_target_device()
    iocs = load_known_iocs()

    all_pkg_res = run_shell_checked(device, "pm list packages -f -U", timeout=30.0)
    third_party_res = run_shell_checked(device, "pm list packages -3 -f -U", timeout=30.0)
    disabled_res = run_shell_checked(device, "pm list packages -d -f", timeout=30.0)

    all_packages = parse_pm_list_packages(all_pkg_res["output"])
    third_party_packages = parse_pm_list_packages(third_party_res["output"])
    third_party_names = {entry["package"] for entry in third_party_packages}

    apk_paths = sorted({entry["apk_path"] for entry in all_packages if entry["apk_path"]})
    apk_hashes = compute_remote_sha256_map(device, apk_paths)

    known_hashes: dict[str, dict[str, str]] = iocs["hashes"]
    known_packages: set[str] = set(iocs["packages"])

    package_name_matches: list[dict[str, Any]] = []
    keyword_matches: list[dict[str, Any]] = []
    hash_matches: list[dict[str, Any]] = []

    for entry in all_packages:
        pkg_name = entry["package"]
        apk_path = entry["apk_path"]
        sha256 = apk_hashes.get(apk_path, "")
        enriched_entry = {
            **entry,
            "is_third_party": pkg_name in third_party_names,
            "sha256": sha256,
        }
        if pkg_name in known_packages:
            package_name_matches.append(enriched_entry)
        if any(keyword in pkg_name.lower() or keyword in apk_path.lower() for keyword in SUSPICIOUS_PACKAGE_KEYWORDS):
            keyword_matches.append(enriched_entry)
        if sha256 and sha256 in known_hashes:
            hash_matches.append({
                **enriched_entry,
                "ioc_match": known_hashes[sha256],
            })

    binary_scan = scan_suspicious_binaries(device)
    binary_hash_matches = [
        {
            "path": path,
            "sha256": digest,
            "ioc_match": known_hashes[digest],
        }
        for path, digest in binary_scan["sha256"].items()
        if digest in known_hashes
    ]

    report = {
        "total_packages": len(all_packages),
        "third_party_packages_count": len(third_party_packages),
        "hashed_apks_count": len(apk_hashes),
        "package_name_matches": package_name_matches,
        "keyword_matches": keyword_matches,
        "apk_hash_matches": hash_matches,
        "binary_hash_matches": binary_hash_matches,
        "binary_scan": binary_scan,
        "third_party_packages": third_party_packages,
        "disabled_packages_raw": disabled_res["output"],
        "all_packages": [
            {
                **entry,
                "is_third_party": entry["package"] in third_party_names,
                "sha256": apk_hashes.get(entry["apk_path"], ""),
            }
            for entry in all_packages
        ],
    }
    output_file = save_json_evidence("02_packages_and_hashes/package_ioc_audit.json", report)
    print(f"Saved package & IOC audit to: {output_file}")
    print(f"Total packages: {len(all_packages)}, Third-party: {len(third_party_packages)}, Hashed APKs: {len(apk_hashes)}")
    print(f"Exact IOC package matches: {len(package_name_matches)}")
    print(f"Keyword matches: {len(keyword_matches)}")
    print(f"Exact APK SHA256 matches: {len(hash_matches)}")
    print(f"Exact Binary SHA256 matches: {len(binary_hash_matches)}")
    return report


if __name__ == "__main__":
    run_package_and_ioc_audit()
