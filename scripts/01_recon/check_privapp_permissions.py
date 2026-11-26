"""Inspect privapp-permissions and platform XML configs for com.oemservice and OEM packages."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.adb_helpers import connect_target_device, run_shell_checked, save_json_evidence


def check_permissions_configs() -> None:
    """Search permission XML directories on device for OEM/XCPE package entries."""
    device = connect_target_device()
    grep_cmd = (
        "grep -rnE 'com\\.oemservice|xcpe|com\\.oem\\.qa|com\\.sdt|mecool|videostrong' "
        "/system/etc/permissions /system_ext/etc/permissions /product/etc/permissions /vendor/etc/permissions 2>/dev/null"
    )
    grep_res = run_shell_checked(device, grep_cmd, timeout=20.0)
    oem_sys_configs = run_shell_checked(
        device,
        "grep -rnE 'com\\.oemservice|xcpe|com\\.oem\\.qa|com\\.sdt|mecool|videostrong' /system/etc/sysconfig /product/etc/sysconfig /vendor/etc/sysconfig 2>/dev/null",
        timeout=20.0,
    )
    payload = {
        "permissions_grep": grep_res,
        "sysconfig_grep": oem_sys_configs,
    }
    save_json_evidence("01_recon/privapp_permissions_grep.json", payload)
    print("=== PERMISSIONS XML GREP ===")
    print(grep_res["output"])
    print("=== SYSCONFIG XML GREP ===")
    print(oem_sys_configs["output"])


if __name__ == "__main__":
    check_permissions_configs()
