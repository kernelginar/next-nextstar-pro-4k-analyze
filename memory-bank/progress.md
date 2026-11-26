# Investigation Progress Log

## [2026-11-25] Phase 1–5: Initial Google Threat Intelligence Audit
- Completed device profiling, 143-APK hashing, runtime/socket audit, and `jadx` decompilation + static IOC scanning of 15 APKs.
- Identified `com.oemservice` (`/system/priv-app/app_xcpe_preset/app_xcpe_preset.apk`, 25,155 bytes, SHA256 `7316469f...`) as an inactive `/oem` preset-upgrader stub.

## [2026-11-25] Phase 6: Gap Closure Against `github-resources` (`synthient_public_research.md` & `xcpe_guard_false_positive_alert.md`)
- Parsed 179 file hashes, 5 certificate fingerprints, 85 network hosts, and 4 SDK IDs from `synthient_public_research.md`.
- Ran `scripts/02_packages_and_hashes/audit_synthient_gap_checks.py` -> saved `evidence/02_packages_and_hashes/synthient_gap_audit.json`.
  - Confirmed `com.oemservice` v1.2.1 (`7316469f...`) matches Synthient line 270, but static code inspection proves it is a **False Positive** in Synthient's bulk table (matches `xcpe_guard_false_positive_alert.md` exact diagnosis: benign Skyworth BSP stub, 25,155 bytes, no MQTT/C2/keylogger).
  - Verified all compound IoCs negative: `AccessibilityKeyDetector` absent (`enabled_accessibility_services=null`, only TalkBack/SwitchAccess/`SdtProductTest` AccService installed), `persist.networkstack.*` absent, `package_verifier_user_consent=1`, `private_dns_mode=null`, all 14 native/JAR artifacts absent.
- Ran `scripts/04_extraction_and_decompile/scan_synthient_iocs.py` -> saved `evidence/04_extraction_and_decompile/synthient_decompiled_scan.json` (0 malicious host/SDK/behavioral hits across 15 APKs).
- Ran `scripts/02_packages_and_hashes/verify_v2_v3_certs.py` -> saved `evidence/02_packages_and_hashes/apk_v2_v3_cert_audit.json` (0 Videostrong/Yoka cert matches across all 15 pulled APKs, including v2/v3-signed `SdtUpdate.apk` and `NextIPTV.apk`).
- Updated `memory-bank/findings.md` with full reconciliation.
