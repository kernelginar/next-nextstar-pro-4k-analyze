"""Inspect /vendor/etc/skyconfig and remaining OEM system configs on device."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.adb_helpers import WORKSPACE_ROOT, connect_target_device, run_shell_checked, save_json_evidence


def inspect_skyconfig() -> None:
    """List and read /vendor/etc/skyconfig and check for any other /oem or /data/vendor configs."""
    device = connect_target_device()
    listing = run_shell_checked(device, "ls -laR /vendor/etc/skyconfig /system/etc/skyconfig /product/etc/skyconfig 2>&1")
    config_props = run_shell_checked(device, "cat /vendor/etc/skyconfig/config.properties 2>&1")
    build_props = run_shell_checked(device, "cat /system/build.prop /vendor/build.prop /product/etc/build.prop 2>/dev/null | grep -iE 'cpe|xcpe|mecool|videostrong|skyworth|sdt|ota|tms|oem'")

    target_dir = WORKSPACE_ROOT / "pulled_artifacts" / "vendor_configs"
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "skyconfig_config.properties").write_text(config_props["output"], encoding="utf-8")

    save_json_evidence("01_recon/skyconfig_and_build_props.json", {
        "listing": listing,
        "config_properties": config_props,
        "filtered_build_props": build_props,
    })
    print("=== SKYCONFIG LISTING ===")
    print(listing["output"])
    print("=== config.properties ===")
    print(config_props["output"])
    print("=== FILTERED BUILD PROPS ===")
    print(build_props["output"])


if __name__ == "__main__":
    inspect_skyconfig()
