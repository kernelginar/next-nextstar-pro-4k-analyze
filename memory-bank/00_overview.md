# XCPE Botnet Forensic Analysis - Next NextStar 4K TV Box

## Target Device
- **Device Serial (ADB):** `90094381518171`
- **Target Product:** Next NextStar 4K TV Box
- **Threat Model:** Videostrong / XCPE Botnet (`x.cpe`, `com.oemservice`, `com.abc.nexus`, `com.vs.grass`, `com.newtv.cboxtv`, `com.ota.service`, `com.android.sso.auth.handler`, affiliate residential proxy / ad-fraud modules, `/oem/` persistence, Play Protect tampering).

## Workspace Structure
- `scripts/common/`: Shared `adbutils` device connection and artifact persistence utilities.
- `scripts/01_recon/`: System properties, hardware/OEM identification, partition & `/oem/` inspection.
- `scripts/02_packages_and_hashes/`: Package enumeration, APK extraction/hashing, IOC matching against Google Threat Intelligence datasets.
- `scripts/03_runtime_and_network/`: Process list, network sockets, system settings, and service inspection.
- `scripts/04_extraction_and_decompile/`: Artifact pulling and `jadx` decompilation automation.
- `evidence/`: Timestamped JSON and raw command outputs from device queries.
- `pulled_artifacts/`: Extracted APKs, ELF binaries, and configuration files.
- `decompiled/`: `jadx` decompiled output for static analysis.
- `memory-bank/`: Chronological logs and distilled findings.
