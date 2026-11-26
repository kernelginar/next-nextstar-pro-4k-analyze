"""Phase 4 script: pull target APKs, ELF binaries, and config files via adbutils and decompile APKs with jadx."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.adb_helpers import WORKSPACE_ROOT, connect_target_device, save_json_evidence

PULLED_DIR: Path = WORKSPACE_ROOT / "pulled_artifacts"
DECOMPILED_DIR: Path = WORKSPACE_ROOT / "decompiled"
JADX_BAT: Path = WORKSPACE_ROOT / "jadx" / "bin" / "jadx.bat"
SHA256_CHUNK_SIZE: int = 65536


def compute_local_sha256(file_path: Path) -> str:
    """Compute SHA256 digest of a local file."""
    hasher = hashlib.sha256()
    with file_path.open("rb") as handle:
        while chunk := handle.read(SHA256_CHUNK_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()


def pull_remote_file(device: Any, remote_path: str, local_subdir: str) -> dict[str, Any]:
    """Pull a file from the device into pulled_artifacts using adbutils sync.pull."""
    relative_name = Path(remote_path).name
    target_dir = PULLED_DIR / local_subdir
    target_dir.mkdir(parents=True, exist_ok=True)
    local_path = target_dir / relative_name
    device.sync.pull(remote_path, str(local_path))
    digest = compute_local_sha256(local_path)
    return {
        "remote_path": remote_path,
        "local_path": str(local_path),
        "size_bytes": local_path.stat().st_size,
        "sha256": digest,
    }


def decompile_apk_with_jadx(apk_path: Path, output_name: str) -> dict[str, Any]:
    """Run jadx.bat to decompile a pulled APK into the decompiled directory."""
    if not JADX_BAT.exists():
        raise FileNotFoundError(f"jadx.bat not found at {JADX_BAT}")
    target_out = DECOMPILED_DIR / output_name
    target_out.mkdir(parents=True, exist_ok=True)
    command = [
        str(JADX_BAT),
        "-d",
        str(target_out),
        "--show-bad-code",
        str(apk_path),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return {
        "apk_path": str(apk_path),
        "output_dir": str(target_out),
        "returncode": completed.returncode,
        "stdout_tail": completed.stdout[-2000:],
        "stderr_tail": completed.stderr[-2000:],
    }


def pull_and_decompile_targets(targets: list[tuple[str, str, bool]]) -> dict[str, Any]:
    """Pull a list of (remote_path, subdir, should_decompile) entries and decompile APKs."""
    device = connect_target_device()
    pulled_records: list[dict[str, Any]] = []
    decompiled_records: list[dict[str, Any]] = []

    for remote_path, subdir, should_decompile in targets:
        try:
            record = pull_remote_file(device, remote_path, subdir)
            pulled_records.append(record)
            print(f"Pulled {remote_path} -> {record['local_path']} (sha256={record['sha256']})")
            if should_decompile:
                apk_local = Path(record["local_path"])
                decompile_name = f"{subdir}__{apk_local.stem}"
                dec_record = decompile_apk_with_jadx(apk_local, decompile_name)
                decompiled_records.append(dec_record)
                print(f"Decompiled {apk_local.name} -> {dec_record['output_dir']} (rc={dec_record['returncode']})")
        except Exception as exc:
            pulled_records.append({
                "remote_path": remote_path,
                "error": str(exc),
            })
            print(f"Failed for {remote_path}: {exc}")

    summary = {
        "pulled": pulled_records,
        "decompiled": decompiled_records,
    }
    save_json_evidence("04_extraction_and_decompile/extraction_manifest.json", summary)
    return summary


if __name__ == "__main__":
    default_targets: list[tuple[str, str, bool]] = [
        ("/oem/oem.prop", "oem_configs", False),
        ("/oem/FLIC", "oem_configs", False),
        ("/oem/rtkimage/fw_info.txt", "oem_configs", False),
        ("/vendor/etc/init/init.common.oem.mount.rc", "init_configs", False),
        ("/vendor/etc/init/init.skyworth.rc", "init_configs", False),
        ("/system/priv-app/app_xcpe_preset/app_xcpe_preset.apk", "system_priv_apps", True),
        ("/system/priv-app/BoxFactoryTest_preset/BoxFactoryTest_preset.apk", "system_priv_apps", True),
        ("/system/priv-app/SdtUpdate/SdtUpdate.apk", "system_priv_apps", True),
        ("/system/priv-app/SdtGlobalKeyHandler/SdtGlobalKeyHandler.apk", "system_priv_apps", True),
        ("/system/app/SdtRcuPair/SdtRcuPair.apk", "system_apps", True),
        ("/system/app/SdtProductTest/SdtProductTest.apk", "system_apps", True),
        ("/system/app/SdtDeviceInfo/SdtDeviceInfo.apk", "system_apps", True),
        ("/oem/app/SdtBackUpAppManager.apk", "oem_apps", True),
        ("/oem/app/com.next.roket.apk", "oem_apps", True),
        ("/oem/app/JetTV.apk", "oem_apps", True),
        ("/oem/app/NextIPTV.apk", "oem_apps", True),
    ]
    pull_and_decompile_targets(default_targets)
