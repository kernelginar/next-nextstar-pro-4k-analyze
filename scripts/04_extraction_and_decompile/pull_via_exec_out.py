"""Pull files that adbd sync cannot access directly by streaming base64 content via adbutils shell."""

from __future__ import annotations

import base64
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


def pull_via_base64_shell(device: Any, remote_path: str, local_subdir: str) -> dict[str, Any]:
    """Read a remote file via base64-encoded adbutils shell2 output and verify SHA256."""
    target_dir = PULLED_DIR / local_subdir
    target_dir.mkdir(parents=True, exist_ok=True)
    local_path = target_dir / Path(remote_path).name

    result = device.shell2(f"base64 '{remote_path}'", timeout=120.0)
    if result.returncode != 0 or not result.output.strip():
        raise RuntimeError(f"base64 read failed (rc={result.returncode}) for {remote_path}: {result.output[:200]}")

    raw_bytes = base64.b64decode(result.output.strip())
    local_path.write_bytes(raw_bytes)
    digest = hashlib.sha256(raw_bytes).hexdigest()
    return {
        "remote_path": remote_path,
        "local_path": str(local_path),
        "size_bytes": len(raw_bytes),
        "sha256": digest,
    }


def decompile_apk(apk_path: Path, output_name: str) -> dict[str, Any]:
    """Decompile an APK using jadx.bat into the decompiled workspace directory."""
    target_out = DECOMPILED_DIR / output_name
    target_out.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [str(JADX_BAT), "-d", str(target_out), "--show-bad-code", str(apk_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "apk_path": str(apk_path),
        "output_dir": str(target_out),
        "returncode": completed.returncode,
    }


def main() -> None:
    """Pull /oem configs and /oem/app APKs and decompile the APKs."""
    device = connect_target_device()
    targets: list[tuple[str, str, bool]] = [
        ("/oem/oem.prop", "oem_configs", False),
        ("/oem/FLIC", "oem_configs", False),
        ("/oem/rtkimage/fw_info.txt", "oem_configs", False),
        ("/oem/app/SdtBackUpAppManager.apk", "oem_apps", True),
        ("/oem/app/com.next.roket.apk", "oem_apps", True),
        ("/oem/app/JetTV.apk", "oem_apps", True),
        ("/oem/app/NextIPTV.apk", "oem_apps", True),
    ]
    pulled: list[dict[str, Any]] = []
    decompiled: list[dict[str, Any]] = []

    for remote_path, subdir, should_decompile in targets:
        try:
            record = pull_via_base64_shell(device, remote_path, subdir)
            pulled.append(record)
            print(f"Pulled {remote_path} ({record['size_bytes']} bytes, sha256={record['sha256']})")
            if should_decompile:
                apk_local = Path(record["local_path"])
                dec = decompile_apk(apk_local, f"{subdir}__{apk_local.stem}")
                decompiled.append(dec)
                print(f"Decompiled {apk_local.name} -> {dec['output_dir']} (rc={dec['returncode']})")
        except Exception as exc:
            pulled.append({"remote_path": remote_path, "error": str(exc)})
            print(f"Failed {remote_path}: {exc}")

    save_json_evidence(
        "04_extraction_and_decompile/oem_extraction_manifest.json",
        {"pulled": pulled, "decompiled": decompiled},
    )


if __name__ == "__main__":
    main()
