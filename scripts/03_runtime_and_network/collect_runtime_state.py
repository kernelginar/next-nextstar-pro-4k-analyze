"""Phase 3 script: collect running processes, network connections, services, and system security settings."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.adb_helpers import connect_target_device, run_shell_checked, save_json_evidence

RUNTIME_COMMANDS: dict[str, str] = {
    "ps": "ps -A -o USER,PID,PPID,VSZ,RSS,WCHAN,ADDR,S,NAME",
    "netstat": "netstat -tunap 2>&1 || ss -tunap 2>&1",
    "proc_net_tcp": "cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>&1",
    "ip_addr": "ip addr show; ip route show",
    "dns_props": "getprop | grep -iE 'dns|proxy|http|mqtt|server|ota|url'",
    "settings_global": "settings list global",
    "settings_secure": "settings list secure",
    "service_list": "service list",
    "dumpsys_activity_services": "dumpsys activity services | grep -E 'ServiceRecord|intent=|packageName=|app=ProcessRecord' | head -n 300",
    "logcat_recent": "logcat -d -t 500 2>&1",
}


def collect_runtime_state() -> dict[str, Any]:
    """Capture live processes, network sockets, services, settings, and recent logcat."""
    device = connect_target_device()
    results: dict[str, Any] = {}
    for label, command in RUNTIME_COMMANDS.items():
        results[label] = run_shell_checked(device, command, timeout=45.0)

    output_file = save_json_evidence("03_runtime_and_network/runtime_state.json", results)
    print(f"Saved runtime state to: {output_file}")
    for label, entry in results.items():
        line_count = len(entry["output"].splitlines())
        print(f"  {label}: rc={entry['returncode']}, lines={line_count}")
    return results


if __name__ == "__main__":
    collect_runtime_state()
