"""Deep filesystem and network configuration check for persistence, hidden files, hosts, and extra APKs."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.adb_helpers import connect_target_device, run_shell_checked, save_json_evidence

EXTRA_CHECKS: dict[str, str] = {
    "etc_hosts": "cat /etc/hosts 2>&1",
    "vendor_ta_inactive": "ls -laR /vendor/ta_inactive 2>&1 | head -n 200",
    "oem_modules": "ls -laR /oem/lib 2>&1",
    "data_system_packages_list": "ls -la /data/local /data/vendor /sdcard /sdcard/Download 2>&1",
    "resolv_and_dns": "getprop | grep -iE 'net\\.dns|dhcp\\.|wifi\\.'",
    "app_ops_oemservice": "cmd appops get com.oemservice 2>&1",
    "dumpsys_netstats_summary": "dumpsys netstats | grep -iE 'uid=1000|uid=10030|uid=10076|com\\.oemservice|com\\.sdt|com\\.next' | head -n 100",
    "logcat_boot_full_oem": "logcat -d | grep -iE 'BootReceiver|UpgradeService|x\\.cpe|persist\\.sys\\.cpe|SdtBackUpAppManager|SdtUpdate|SdtProductTest|DaemonService|mecool' | head -n 200",
    "cert_check_system_apps": "ls -la /system/app/SdtFrontPanelLedsService /system/app/SdtGtvPartnerConfig /system/app/RtkPartnerInterface /system/priv-app/axel 2>&1",
}


def run_deep_checks() -> None:
    """Collect extra filesystem, netstats, appops, and boot logcat checks."""
    device = connect_target_device()
    results: dict[str, Any] = {}
    for label, command in EXTRA_CHECKS.items():
        results[label] = run_shell_checked(device, command, timeout=25.0)
    out_path = save_json_evidence("03_runtime_and_network/deep_fs_and_net_checks.json", results)
    print(f"Saved deep checks to: {out_path}")
    for label, entry in results.items():
        print(f"=== {label} (rc={entry['returncode']}) ===")
        print(entry["output"][:1500])


if __name__ == "__main__":
    run_deep_checks()
