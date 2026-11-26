"""Shared ADB connection and evidence logging utilities built on adbutils."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

import adbutils

TARGET_DEVICE_SERIAL: str = "90094381518171"
DEFAULT_ADB_HOST: str = "127.0.0.1"
DEFAULT_ADB_PORT: int = 5037
DEFAULT_SOCKET_TIMEOUT_SECONDS: float = 15.0
WORKSPACE_ROOT: Path = Path(__file__).resolve().parents[2]
EVIDENCE_DIR: Path = WORKSPACE_ROOT / "evidence"


def connect_target_device(serial: str = TARGET_DEVICE_SERIAL) -> adbutils.AdbDevice:
    """Connect to the specified ADB device via adbutils and return the device handle."""
    client = adbutils.AdbClient(
        host=DEFAULT_ADB_HOST,
        port=DEFAULT_ADB_PORT,
        socket_timeout=DEFAULT_SOCKET_TIMEOUT_SECONDS,
    )
    available_devices = client.device_list()
    for device in available_devices:
        if device.serial == serial:
            return device
    raise RuntimeError(f"Target ADB device not found: {serial}")


def run_shell_checked(device: adbutils.AdbDevice, command: str, timeout: float = 30.0) -> dict[str, Any]:
    """Execute a shell command on the device using shell2 and return structured output."""
    result = device.shell2(command, timeout=timeout)
    return {
        "command": command,
        "returncode": result.returncode,
        "output": result.output,
    }


def save_json_evidence(relative_path: str, payload: Any) -> Path:
    """Persist structured evidence data as formatted JSON under the evidence directory."""
    output_path = EVIDENCE_DIR / relative_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    enriched_payload = {
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "device_serial": TARGET_DEVICE_SERIAL,
        "data": payload,
    }
    output_path.write_text(json.dumps(enriched_payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return output_path
