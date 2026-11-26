"""Inspect detailed package dumps, folder contents, and XCPE-related logs on the device."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.adb_helpers import connect_target_device, run_shell_checked, save_json_evidence

TARGET_PACKAGES: tuple[str, ...] = (
    "com.oemservice",
    "com.oem.qa",
    "com.sdt.backupappmanger",
    "com.sdt.ota",
    "com.sdt.producttest",
    "com.sdt.mecoolrcupair",
    "com.sdt.deviceinfo",
    "com.sdt.globalkey",
    "com.next.roket",
    "com.next.iptv",
    "com.jettv.player",
)


def inspect_targets() -> dict[str, Any]:
    """Collect dumpsys package details, priv-app listings, and logcat IOC hits."""
    device = connect_target_device()
    dumps: dict[str, Any] = {}
    for package_name in TARGET_PACKAGES:
        dumps[package_name] = run_shell_checked(device, f"dumpsys package {package_name}", timeout=20.0)

    extra_checks = {
        "app_xcpe_preset_dir": run_shell_checked(device, "ls -laR /system/priv-app/app_xcpe_preset", timeout=15.0),
        "box_factory_dir": run_shell_checked(device, "ls -laR /system/priv-app/BoxFactoryTest_preset", timeout=15.0),
        "sdt_dirs": run_shell_checked(device, "ls -laR /system/app/Sdt* /system/priv-app/Sdt*", timeout=15.0),
        "logcat_grep": run_shell_checked(
            device,
            "logcat -d | grep -iE 'xcpe|oemservice|nexus|szbboys|anyev|mqtt|mecool|videostrong|producttest|backupapp' | tail -n 200",
            timeout=20.0,
        ),
        "dumpsys_jobscheduler": run_shell_checked(
            device,
            "dumpsys jobscheduler | grep -iE 'JOB #|com\\.oemservice|com\\.sdt|com\\.next|com\\.oem\\.qa' | head -n 200",
            timeout=20.0,
        ),
        "dumpsys_alarm": run_shell_checked(
            device,
            "dumpsys alarm | grep -iE 'com\\.oemservice|com\\.sdt|com\\.next|com\\.oem\\.qa' | head -n 100",
            timeout=20.0,
        ),
    }

    payload = {
        "package_dumps": dumps,
        "extra_checks": extra_checks,
    }
    output_path = save_json_evidence("03_runtime_and_network/target_package_details.json", payload)
    print(f"Saved target package details to: {output_path}")
    return payload


if __name__ == "__main__":
    inspect_targets()
