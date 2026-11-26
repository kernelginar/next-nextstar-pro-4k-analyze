# Consolidated Technical Findings (Verified Evidence)

## 1. Device Identity, Verified Boot & Firmware Provenance
- **ADB Serial:** `90094381518171`
- **Brand / Model:** `Next` / `UHD Google TV STB` (`RMQ`, board `HPR3A1325_4K`)
- **Manufacturer (Build & Signing Key):** `SkyworthDigital` (`CN=skydigital, OU=SKYWORTH, O=SKYWORTH, L=ShenZhen, ST=GuangDong, C=CN`, `skydigital@skyworth.com`, cert SHA256 `12:BF:50:A0:3F:1E:D9:C9:1A:6C:0A:E0:B7:8D:CA:88:2C:70:05:88:5A:17:8A:ED:D5:49:CD:A2:7F:DE:60:1C`)
- **Build Fingerprint:** `Next/HPR314-Next/RMQ:14/UTT1.250214.001/C1.0.8_20260520:user/release-keys`
- **Android Version / Patch / Kernel:** Android 14, Security Patch `2026-05-05`, Kernel `5.15.180-android14-11-gdd24a7efe6fe-dirty`
- **Verified Boot & `/oem` Integrity:**
  - `ro.boot.verifiedbootstate = green`, `ro.boot.veritymode = enforcing`, `ro.boot.flash.locked = 1`, `ro.boot.vbmeta.device_state = locked`, `ro.boot.securebootstate = 1`
  - `/oem` is mounted read-only (`ro`) on `/dev/block/dm-19` (`partition.oem.verified = 2`, SHA-256 verified).

## 2. Critical Reconciliation: `com.oemservice` (`app_xcpe_preset.apk`) vs. Synthient & `xcpe-guard`
- **Location on Device:** `/system/priv-app/app_xcpe_preset/app_xcpe_preset.apk` (exact size: **25,155 bytes**)
- **SHA256:** `7316469fd5b9fa633d9474a14b72716b9ceb4bbf656725ab79409da608eda2be` (`versionCode=2`, `versionName=1.2.1`)
- **Synthient Table vs. Code Reality:**
  - `github-resources/synthient_public_research.md` (line 270) lists this **exact SHA256** (`7316469f...`, `1.2.1`, `2025-06-28`) with the generic label `"x.cpe device MQTT backdoor."`.
  - Direct `jadx` decompilation of `app_xcpe_preset.apk` proves that `7316469f...` v1.2.1 contains **NO MQTT client, NO C2 domains/IPs, NO `SurfaceControl`, NO `AccessibilityKeyDetector`, and NO shell execution**. It contains only `x.cpe.receiver.BootReceiver` + `x.cpe.UpgradeService`, matching the **clean SkyworthDigital BSP `/oem` preset-installer stub** described in `github-resources/xcpe_guard_false_positive_alert.md` (~21-25 KB).
  - Synthient's own KM9PRO reference device (`HPR311-MECOOL`, `Manufacturer: SkyworthDigital`, `Board: HPR3A1325_4K`, `SoC: Realtek RTD1325`, `RMQ`) shares the exact same SkyworthDigital RTD1325 BSP (`SdtDeviceInfo`, `SdtFrontPanelLedsService`, `SdtProductTest`, `SdtRcuPair`, `SdtUpdate`, `SdtCustomizationConfiguration`), explaining why `com.oemservice` v1.2.1 (`7316469f...`) appeared in Synthient's bulk artifact collection alongside genuine `x.cpe` v5.x/6.x MQTT backdoor payloads.
- **Architectural Risk Note:** Although benign in its current 25 KB stub form on this box, `/system/etc/permissions/privapp-permissions-SkyworthDigital.xml` (lines 68-119) still pre-grants `com.oemservice` 51 privileged permissions (`READ_FRAME_BUFFER`, `INJECT_EVENTS`, `WRITE_SECURE_SETTINGS`, `GRANT_RUNTIME_PERMISSIONS`, etc.) under `android.uid.system`.

## 3. Compound IoC Verification (`xcpe-guard` + Synthient `github-resources`)
- **Malicious Package Check (`x.cpe`, `com.abc.nexus`, `com.vs.grass`, `com.android.system.ntp`, `com.android.sso.auth.handler`, `com.gaganode*`, `com.newtv.cboxtv`, `com.ota.service`, `com.android.init.android`):** **0** found.
- **Play Protect Consent:** `package_verifier_user_consent = 1` (not tampered to `-1`).
- **Accessibility Services (`enabled_accessibility_services=null`, `accessibility_enabled=0`):** Installed services are only `TalkBackService`, `SwitchAccessService`, and `com.sdt.producttest/com.sdt.projector.AccService` (disabled). **No `AccessibilityKeyDetector`**.
- **Properties (`persist.networkstack.*`, `persist.sys.cpe.*`, `uota`, `yoka`, `titannet`, `airship`, `grass`, `gaganode`, `allcloud`):** **0** suspicious properties (`vold.has_quota=1` only).
- **Private DNS (`private_dns_mode`, `private_dns_specifier`):** Both `null` (default/unmodified).
- **Native Binary Scan (`airship`, `grass_android_2.0`, `lw_android_agent*`, `videoadtime_pproxy*`, `libjaguar.so`, `libseccomp_guard.so`, `libfleetshare.so`, `libexploit.so`, `libnative_keys.so`, `nat-checker`, `frp-lite.jar`, `ol_imp_30737.jar`, `backup_7.jar`, `static_host_20260206.jar`):** **0** found across `/system`, `/vendor`, `/product`, `/system_ext`, `/oem`, `/data/local/tmp`.
- **Expanded Synthient Hashes (179 SHA256), Certs (5 SHA256), Hosts (85), & SDK IDs (4):**
  - 143/143 installed APKs: **1** hash match only (`7316469f...` = the 25 KB `com.oemservice` v1.2.1 stub itself).
  - 15/15 pulled APKs v1/v2/v3 signing certs (`apk_v2_v3_cert_audit.json`): **0** matches against Videostrong/Yoka/Nexus certificates (`f90a646f...`, `9f6e3ba0...`, `17d97cb3...`, etc.).
  - 15/15 decompiled APKs (`synthient_decompiled_scan.json`): **0** SDK ID hits, **0** `AccessibilityKeyDetector`/`persist.networkstack`/`uota` hits, **0** malicious domain hits (`github.com` appeared only in benign OSS library comments/RxJava/Firebase/public-suffix-list).
- **User Storage (`/sdcard/Download/`):** `inat-box-update-v14.apk` and `inat-box-v14-inattvproapkindir-tr (1).apk` (SHA256 `bfb72861997316a0c5fe691af7fd6937abf75c277d7afd5600d524e26ba56ac4`): Not installed, not in Synthient's 179 hashes.
