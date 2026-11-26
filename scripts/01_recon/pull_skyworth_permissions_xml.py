"""Pull SkyworthDigital privapp-permissions XML and list custom permission files."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.adb_helpers import WORKSPACE_ROOT, connect_target_device, run_shell_checked


def pull_permissions_xml() -> None:
    """Pull privapp-permissions-SkyworthDigital.xml and print its contents."""
    device = connect_target_device()
    listing = run_shell_checked(device, "ls -la /system/etc/permissions/*Skyworth* /system/etc/permissions/*oem* /system/etc/permissions/*sdt* /product/etc/permissions/* 2>&1")
    print("=== PERMISSION FILES ===")
    print(listing["output"])

    target_dir = WORKSPACE_ROOT / "pulled_artifacts" / "system_configs"
    target_dir.mkdir(parents=True, exist_ok=True)
    local_xml = target_dir / "privapp-permissions-SkyworthDigital.xml"
    device.sync.pull("/system/etc/permissions/privapp-permissions-SkyworthDigital.xml", str(local_xml))
    print("=== privapp-permissions-SkyworthDigital.xml ===")
    print(local_xml.read_text(encoding="utf-8"))


if __name__ == "__main__":
    pull_permissions_xml()
