"""Verify v2/v3 APK signing certificate SHA256 fingerprints against Synthient Videostrong cert IOCs."""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.adb_helpers import WORKSPACE_ROOT, save_json_evidence

APK_SIG_BLOCK_MAGIC: bytes = b"APK Sig Block 42"
APK_V2_SCHEME_ID: int = 0x7109871A
APK_V3_SCHEME_ID: int = 0xF05368C0
SYNTHIENT_MALICIOUS_CERTS: set[str] = {
    "98151b82dcd1605f3500104e8a56735a294866917d0e0cb056a4f8bbd464f947",
    "68d4874c5bd8535fc5b3f2cd75dc19dede89e3792c441d44ba51b1143e0867a1",
    "17d97cb33ffa9ee04a47720ed79faf2985a85f4fabcfd98ccce26524e6ce562e",
    "9f6e3ba0389ee113e3cd861c57a4f39771c77ddb040a209bd919e5adc55b506b",
    "f90a646f51f4b9a96694ccad099b20e97a1556c81c4fa3375dd6c42e8198231f",
}


def extract_v2_v3_cert_sha256(apk_path: Path) -> list[str]:
    """Extract X.509 certificate SHA256 digests from an APK Signing Block v2/v3."""
    raw = apk_path.read_bytes()
    magic_index = raw.rfind(APK_SIG_BLOCK_MAGIC)
    if magic_index < 24:
        return []
    block_size = struct.unpack("<Q", raw[magic_index - 8 : magic_index])[0]
    block_start = magic_index + 16 - block_size - 8
    pos = block_start + 8
    end = magic_index - 8

    digests: list[str] = []
    while pos + 12 <= end:
        pair_len = struct.unpack("<Q", raw[pos : pos + 8])[0]
        pair_id = struct.unpack("<I", raw[pos + 8 : pos + 12])[0]
        value = raw[pos + 12 : pos + 8 + pair_len]
        pos += 8 + pair_len
        if pair_id not in (APK_V2_SCHEME_ID, APK_V3_SCHEME_ID):
            continue
        signers_len = struct.unpack("<I", value[0:4])[0]
        s_pos = 4
        while s_pos < 4 + signers_len:
            signer_len = struct.unpack("<I", value[s_pos : s_pos + 4])[0]
            signer = value[s_pos + 4 : s_pos + 4 + signer_len]
            s_pos += 4 + signer_len
            signed_data_len = struct.unpack("<I", signer[0:4])[0]
            signed_data = signer[4 : 4 + signed_data_len]
            digests_len = struct.unpack("<I", signed_data[0:4])[0]
            certs_offset = 4 + digests_len
            certs_len = struct.unpack("<I", signed_data[certs_offset : certs_offset + 4])[0]
            c_pos = certs_offset + 4
            while c_pos < certs_offset + 4 + certs_len:
                cert_len = struct.unpack("<I", signed_data[c_pos : c_pos + 4])[0]
                cert_der = signed_data[c_pos + 4 : c_pos + 4 + cert_len]
                c_pos += 4 + cert_len
                digests.append(hashlib.sha256(cert_der).hexdigest())
    return sorted(set(digests))


def main() -> None:
    """Check v2/v3 cert SHA256 digests across all pulled APKs."""
    pulled_root = WORKSPACE_ROOT / "pulled_artifacts"
    results: dict[str, dict[str, object]] = {}
    for apk_path in sorted(pulled_root.rglob("*.apk")):
        certs = extract_v2_v3_cert_sha256(apk_path)
        matches = [c for c in certs if c in SYNTHIENT_MALICIOUS_CERTS]
        results[apk_path.name] = {
            "v2_v3_cert_sha256": certs,
            "malicious_cert_matches": matches,
        }
        print(f"{apk_path.name}: certs={certs}, matches={matches}")
    save_json_evidence("02_packages_and_hashes/apk_v2_v3_cert_audit.json", results)


if __name__ == "__main__":
    main()
