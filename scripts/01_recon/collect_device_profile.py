"""Phase 1 reconnaissance script for Next NextStar 4K TV Box system telemetry and partitions."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.adb_helpers import connect_target_device, run_shell_checked, save_json_evidence

RECON_COMMANDS: dict[str, str] = {
    "id": "id",
    "uname": "uname -a",
    "getprop": "getprop",
    "mount": "mount",
    "df": "df -h",
    "oem_listing": "ls -laR /oem 2>&1",
    "vendor_overlay_listing": "ls -la /vendor/app /vendor/priv-app /system/app /system/priv-app /product/app /product/priv-app /system_ext/app /system_ext/priv-app 2>&1",
    "init_rc_files": "ls -la /init*.rc /vendor/etc/init /system/etc/init /oem/etc/init 2>&1",
    "settings_global_verifier": "settings list global | grep -iE 'verifier|adb|install|proxy|ota'",
    "data_local_tmp": "ls -la /data/local/tmp 2>&1",
}


def parse_getprop_output(raw_output: str) -> dict[str, str]:
    """Parse Android getprop '[key]: [value]' lines into a dictionary."""
    properties: dict[str, str] = {}
    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("[") or "]: [" not in stripped:
            continue
        key_part, value_part = stripped.split("]: [", maxsplit=1)
        key = key_part.lstrip("[")
        value = value_part.rstrip("]")
        properties[key] = value
    return properties


def extract_key_hardware_properties(properties: dict[str, str]) -> dict[str, str]:
    """Extract high-signal hardware, manufacturer, and Videostrong/Mecool indicators."""
    target_prefixes = (
        "ro.product.",
        "ro.build.",
        "ro.hardware",
        "ro.board.",
        "ro.boot.",
        "ro.serialno",
        "ro.mecool.",
        "ro.videostrong.",
        "ro.oem.",
        "ro.vendor.",
        "persist.sys.",
    )
    return {
        key: value
        for key, value in sorted(properties.items())
        if any(key.startswith(prefix) for prefix in target_prefixes) or "videostrong" in value.lower() or "mecool" in value.lower() or "xcpe" in value.lower()
    }


def collect_recon_profile() -> dict[str, Any]:
    """Run phase 1 telemetry commands and save parsed results to evidence."""
    device = connect_target_device()
    raw_results: dict[str, Any] = {}
    for label, command in RECON_COMMANDS.items():
        raw_results[label] = run_shell_checked(device, command, timeout=30.0)

    parsed_props = parse_getprop_output(raw_results["getprop"]["output"])
    highlighted_props = extract_key_hardware_properties(parsed_props)

    profile_summary = {
        "highlighted_properties": highlighted_props,
        "all_properties_count": len(parsed_props),
        "all_properties": parsed_props,
        "command_outputs": raw_results,
    }
    output_file = save_json_evidence("01_recon/device_profile.json", profile_summary)
    print(f"Saved recon profile to: {output_file}")
    print(f"UID / id: {raw_results['id']['output'].strip()}")
    print(f"Kernel: {raw_results['uname']['output'].strip()}")
    print(f"Highlighted props count: {len(highlighted_props)}")
    for key in (
        "ro.product.manufacturer",
        "ro.product.brand",
        "ro.product.model",
        "ro.product.device",
        "ro.product.board",
        "ro.build.fingerprint",
        "ro.build.version.release",
        "ro.build.version.security_patch",
        "ro.mecool.device",
    ):
        if key in parsed_props:
            print(f"  {key} = {parsed_props[key]}")
    return profile_summary


if __name__ == "__main__":
    collect_recon_profile()
