# Next NextStar 4K TV Box — XCPE / Badbox 2.0 Güvenlik ve İnceleme Raporu

Bu çalışma, **Next NextStar 4K TV Box** cihazının Videostrong kaynaklı **XCPE (Badbox 2.0)** botneti ile bağlantılı olup olmadığını doğrulamak amacıyla hazırlanmıştır. İnceleme süreci tamamen `adbutils` kütüphanesi, cihaz üzeri özet (SHA-256) doğrulamaları, ağ/süreç dökümleri ve `jadx` ile statik kaynak kod çözümlemesi üzerinden yürütülmüştür.

Elde edilen bulgular Google Cloud Threat Intelligence (GTIG), Synthient araştırması ve `xcpe-guard` yanlış pozitif uyarısı kapsamında paylaşılan tüm göstergelerle karşılaştırılmıştır.

---

## Temel Sonuç

İncelenen **Next NextStar 4K TV Box** cihazında **aktif bir XCPE botnet enfeksiyonu tespit edilmemiştir**.

* Cihazda çalışan bir MQTT C2 istemcisi, arka kapı yükleyicisi (`com.abc.nexus`, `com.vs.grass`, `com.newtv.cboxtv`, `com.ota.service`, `com.android.sso.auth.handler`), proxy modülü veya reklam sahteciliği (ad-fraud) bileşeni bulunmamaktadır.
* Google Play Protect onayı (`package_verifier_user_consent`) `1` değerindedir. Zararlı yazılımların yaptığı gibi `-1` değerine çekilmemiştir.
* Cihazdaki `/system/priv-app/app_xcpe_preset/app_xcpe_preset.apk` (`com.oemservice`) paketi, paket adı ve SHA-256 özeti nedeniyle bazı otomatik tarama listelerinde "arka kapı" olarak görünmektedir. Statik kaynak kod incelemesi, bu cihazdaki `1.2.1` sürümünün (`25.155` bayt) yalnızca Skyworth Digital referans yazılımında yer alan zararsız bir `/oem` ön-kurulum taslağı (stub) olduğunu kanıtlamıştır.

---

## Cihaz ve Yazılım Kimliği

| Özellik | Gözlenen Değer |
| --- | --- |
| Marka / Model | `Next` / `UHD Google TV STB` |
| Cihaz Kod Adı / Kart | `RMQ` / `HPR3A1325_4K` |
| Üretici (Build ve İmza) | `SkyworthDigital` |
| Yapı Parmak İzi | `Next/HPR314-Next/RMQ:14/UTT1.250214.001/C1.0.8_20260520:user/release-keys` |
| Android / Güvenlik Yaması | Android 14 / `2026-05-05` |
| Çekirdek (Kernel) | `5.15.180-android14-11-gdd24a7efe6fe-dirty` |
| Verified Boot / dm-verity | `green` / `enforcing` |
| Önyükleyici Kilidi | `ro.boot.flash.locked=1`, `ro.boot.vbmeta.device_state=locked` |
| `/oem` Bölümü Durumu | `/dev/block/dm-19` üzerinde salt-okunur (`ro`), SHA-256 doğrulamalı |

---

## Kritik Bulgu: `com.oemservice` (`app_xcpe_preset.apk`) ve Yanlış Pozitif Analizi

Cihazın `/system/priv-app/app_xcpe_preset/app_xcpe_preset.apk` konumunda `com.oemservice` paket adına sahip bir sistem uygulaması yer almaktadır.

* **Dosya Boyutu:** `25.155` bayt
* **Sürüm:** `1.2.1` (`versionCode=2`)
* **SHA-256:** `7316469fd5b9fa633d9474a14b72716b9ceb4bbf656725ab79409da608eda2be`
* **Çalışma Yetkisi:** `android:sharedUserId="android.uid.system"` (`uid=1000`)
* **İmza Sertifikası:** `SkyworthDigital` (`skydigital@skyworth.com`, SHA-256: `12:BF:50:A0:3F:1E:D9:C9:1A:6C:0A:E0:B7:8D:CA:88:2C:70:05:88:5A:17:8A:ED:D5:49:CD:A2:7F:DE:60:1C`)

### Kaynak Kod Ne Yapıyor?

`jadx` ile decompile edilen kaynak kodlar yalnızca dört dosyadan oluşmaktadır (`BuildConfig.java`, `R.java`, `BootReceiver.java`, `UpgradeService.java`).

1. **`x.cpe.receiver.BootReceiver`**: Cihaz açılışında (`BOOT_COMPLETED`, öncelik `1000`) `persist.sys.cpe.show_log` sistem özelliğini okur. Ardından `/oem` kök dizinindeki dosyaları tarar. Paket adı `com.oemservice` olan bir APK bulursa `UpgradeService` servisini başlatır.
2. **`x.cpe.UpgradeService`**: `"New Message"` başlıklı standart bir ön plan bildirimi oluşturur. Parametre olarak gelen APK dosyasını `PackageInstaller` üzerinden sistem yetkisiyle kurar.

Bu APK içerisinde **hiçbir ağ isteği, MQTT istemcisi, C2 alan adı, IP adresi, kabuk komutu çalıştırıcı (`Runtime.exec` / `ProcessBuilder`), ekran yakalama (`SurfaceControl`) veya tuş dinleme (`AccessibilityKeyDetector`) kodu yoktur**.

### Neden Yanlış Pozitif Olarak Görünüyor?

* Synthient raporunda ([synthient_public_research.md](github-resources/synthient_public_research.md)) `7316469fd5b9fa633d9474a14b72716b9ceb4bbf656725ab79409da608eda2be` özeti, toplu veri sınıflandırması nedeniyle `"x.cpe device MQTT backdoor."` etiketiyle listelenmiştir.
* Synthient'in incelediği referans cihaz (`HPR311-MECOOL`, `SkyworthDigital`, `HPR3A1325_4K`, `Realtek RTD1325`) ile bu Next NextStar 4K cihazı aynı `SkyworthDigital` RTD1325 temel yazılımını (`SdtDeviceInfo`, `SdtUpdate`, `SdtProductTest`, `SdtFrontPanelLedsService`) paylaşmaktadır.
* [xcpe_guard_false_positive_alert.md](github-resources/xcpe_guard_false_positive_alert.md) belgesinde açıklandığı üzere temiz Skyworth Digital kutularındaki bu küçük (~21-25 KB) `com.oemservice` uygulaması zararsız bir ön-kurulum taslağıdır. Gerçek enfekte cihazlarda bu taslağın yerini çok daha büyük boyutlu `x.cpe` `5.x` / `6.x` MQTT arka kapısı almaktadır.
* Şu an cihazın `/oem` kök dizininde `com.oemservice` APK dosyası yoktur. `/oem` bölümü AVB/dm-verity ile salt-okunur korunduğu için dışarıdan dosya yazılamaz.

### Mimari İzin Notu

Uygulamanın kendisi pasif bir taslak olsa da `/system/etc/permissions/privapp-permissions-SkyworthDigital.xml` dosyası `com.oemservice` paketine `READ_FRAME_BUFFER`, `INJECT_EVENTS`, `WRITE_SECURE_SETTINGS`, `GRANT_RUNTIME_PERMISSIONS`, `DELETE_PACKAGES` ve `INSTALL_PACKAGE_UPDATES` dahil **51 ayrıcalıklı izin** tanımlamaktadır. Aynı şablon `/system/priv-app/BoxFactoryTest_preset/BoxFactoryTest_preset.apk` (`com.oem.qa`) içinde de `persist.sys.cpe.show_log` ve `/oem` taraması şeklinde yer almaktadır.

---

## Ortak ODM / BSP İzleri

İnceleme sırasında Skyworth Digital ve Videostrong/Mecool altyapısı arasındaki ortak referans yazılım mirasını gösteren iki iz daha gözlenmiştir. Her ikisinin de bu cihazda zararsız olduğu doğrulanmıştır.

* `system/build.prop` dosyası içinde `import /oem/oem.prop ro.mecool.device.model` satırı mevcuttur. Cihazdaki `/oem/oem.prop` dosyasında bu değer tanımlı değildir.
* `/system/app/SdtRcuPair/SdtRcuPair.apk` uygulamasının paket adı `com.sdt.mecoolrcupair` olarak geçmektedir. Kaynak kod incelemesi bu uygulamanın `INTERNET` izni bile olmayan temiz bir Bluetooth kumanda eşleştirme servisi olduğunu doğrulamıştır.

---

## Yapılan Kontroller ve Test Sonuçları

| Kontrol Kategorisi | Kapsam | Sonuç | Kanıt Dosyası |
| --- | --- | --- | --- |
| Yüklü APK Hash Taraması (GTIG) | 143 / 143 APK SHA-256 | 0 zararlı hash eşleşmesi | [package_ioc_audit.json](evidence/02_packages_and_hashes/package_ioc_audit.json) |
| Genişletilmiş Hash Taraması (Synthient) | 179 dosya SHA-256 özeti | Yalnızca temiz `com.oemservice` `1.2.1` (`7316469f...`) | [synthient_gap_audit.json](evidence/02_packages_and_hashes/synthient_gap_audit.json) |
| Paket Adı Kontrolleri | `x.cpe`, `com.abc.nexus`, `com.vs.grass`, `com.android.system.ntp`, `com.android.sso.auth.handler`, `com.gaganode*`, `com.newtv.cboxtv`, `com.ota.service`, `com.android.init.android` | Yalnızca `com.oemservice` mevcut | [synthient_gap_audit.json](evidence/02_packages_and_hashes/synthient_gap_audit.json) |
| Statik Ağ IOC Taraması (GTIG) | 15 decompile APK içinde 169 alan adı / IP / URL | 0 eşleşme | [static_ioc_scan.json](evidence/04_extraction_and_decompile/static_ioc_scan.json) |
| Statik Ağ ve SDK Taraması (Synthient) | 15 decompile APK içinde 85 host ve 4 SDK ID | 0 zararlı eşleşme | [synthient_decompiled_scan.json](evidence/04_extraction_and_decompile/synthient_decompiled_scan.json) |
| APK Sertifika Doğrulaması (v1/v2/v3) | Çekilen 15 APK ile 5 Videostrong/Yoka sertifikası | 0 eşleşme | [apk_v2_v3_cert_audit.json](evidence/02_packages_and_hashes/apk_v2_v3_cert_audit.json) |
| Play Protect Ayarı | `package_verifier_user_consent` | `1` (etkin, müdahale yok) | [synthient_gap_audit.json](evidence/02_packages_and_hashes/synthient_gap_audit.json) |
| Erişilebilirlik Servisleri | `AccessibilityKeyDetector` ve yüklü servisler | Devre dışı (`enabled_accessibility_services=null`), `AccessibilityKeyDetector` yok | [synthient_gap_audit.json](evidence/02_packages_and_hashes/synthient_gap_audit.json) |
| Sistem Özellikleri ve Özel DNS | `persist.networkstack.*`, `private_dns_mode`, `uota`, `yoka` | Şüpheli özellik yok, Özel DNS `null` | [synthient_gap_audit.json](evidence/02_packages_and_hashes/synthient_gap_audit.json) |
| Native İkili Dosya / JAR Taraması | `libseccomp_guard.so`, `libfleetshare.so`, `libjaguar.so`, `libexploit.so`, `libnative_keys.so`, `airship`, `lw_android_agent`, `videoadtime_pproxy`, `frp-lite.jar` vb. | 0 eşleşme | [synthient_gap_audit.json](evidence/02_packages_and_hashes/synthient_gap_audit.json) |
| Ağ Soketleri ve Süreçler | `ps`, `netstat`, `/proc/net/tcp*`, `dumpsys` | Yalnızca standart sistem/Cast/ADB portları | [runtime_state.json](evidence/03_runtime_and_network/runtime_state.json) |

---

## İncelenen OEM ve Üçüncü Taraf Uygulamalar

Aşağıdaki 15 APK dosyası cihazdan çekilip `jadx` ile çözümlenmiştir. Her biri statik kod ve ağ göstergesi açısından incelenmiştir.

* **`/system/priv-app/app_xcpe_preset/app_xcpe_preset.apk`** (`com.oemservice`): Pasif `/oem` ön-kurulum taslağı. C2 veya ağ kodu yok.
* **`/system/priv-app/BoxFactoryTest_preset/BoxFactoryTest_preset.apk`** (`com.oem.qa`): Fabrika test uygulaması taslağı. Ağ kodu yok.
* **`/system/priv-app/SdtUpdate/SdtUpdate.apk`** (`com.sdt.ota`): Skyworth OTA güncelleme istemcisi. `/vendor/etc/skyconfig/config.properties` içindeki `tms_url` boş olduğu için bulut OTA adresi tanımsız.
* **`/system/priv-app/SdtGlobalKeyHandler/SdtGlobalKeyHandler.apk`** (`com.sdt.globalkey`): Uzaktan kumanda kısayol tuşu yönlendiricisi. Ağ kodu yok.
* **`/system/app/SdtRcuPair/SdtRcuPair.apk`** (`com.sdt.mecoolrcupair`): Bluetooth kumanda eşleştirme uygulaması. `INTERNET` izni yok.
* **`/system/app/SdtProductTest/SdtProductTest.apk`** (`com.sdt.producttest`): Fabrika donanım test ve projektör CEC aracı. Yalnızca yerel ağ test uç noktaları içerir.
* **`/system/app/SdtDeviceInfo/SdtDeviceInfo.apk`** (`com.sdt.deviceinfo`): Cihaz seri numarası ve MAC özelliklerini (`dev.com.mft.*`) dolduran sistem aracı. `INTERNET` izni yok.
* **`/system/app/SdtFrontPanelLedsService/SdtFrontPanelLedsService.apk`** (`com.sdt.frontpanelledsservice`): Ön panel LED kontrol servisi. Temiz.
* **`/system/app/SdtGtvPartnerConfig/SdtGtvPartnerConfig.apk`** (`com.sdt.customization`): Google TV başlatıcı partner yapılandırma sağlayıcısı. Temiz.
* **`/system/app/RtkPartnerInterface/RtkPartnerInterface.apk`** (`com.rtk.partnerinterface`): Realtek partner arayüzü. Temiz.
* **`/oem/app/SdtBackUpAppManager.apk`** (`com.sdt.backupappmanger`): Android TV son uygulamalar ve arka plan görev yöneticisi (`QuickstepService`). `INTERNET` izni yok.
* **`/oem/app/com.next.roket.apk`** (`com.next.roket`): Kumanda üzerindeki roket kısayol tuşu uygulaması. `INTERNET` izni yok.
* **`/oem/app/JetTV.apk`** ve güncel `/data/app/.../base.apk` (`com.jettv.player`): Xtream-Codes tabanlı IPTV oynatıcı (`jettv.dyndns.tv`). Cihazda devre dışı durumda.
* **`/oem/app/NextIPTV.apk`** (`com.next.iptv`): Next IPTV istemcisi (`nextmachina3d.com/iptv/`). Cihazda devre dışı durumda.

Ek olarak `/sdcard/Download/` klasöründe kullanıcı tarafından indirilmiş iki APK dosyası (`inat-box-update-v14.apk`, `inat-box-v14-inattvproapkindir-tr (1).apk`, SHA-256: `bfb72861997316a0c5fe691af7fd6937abf75c277d7afd5600d524e26ba56ac4`) görülmüştür. Bu dosyalar sisteme kurulmamıştır ve bilinen XCPE/Synthient hash listelerinde yer almamaktadır.

---

## Depo Yapısı

```text
.
├── README.md
├── adbutils-usage.md
├── quick_summary_about_xcpe_botnet.md
├── github-resources/
│   ├── synthient_public_research.md
│   └── xcpe_guard_false_positive_alert.md
├── samples_from_google_cloud_threat_intelligence/
│   ├── affiliate_malware.md
│   ├── core_malware_samples.md
│   └── network_indicators.md
├── memory-bank/
│   ├── 00_overview.md
│   ├── findings.md
│   ├── final_report.md
│   └── progress.md
├── scripts/
│   ├── common/
│   │   └── adb_helpers.py
│   ├── 01_recon/
│   │   ├── check_privapp_permissions.py
│   │   ├── collect_device_profile.py
│   │   ├── inspect_skyconfig.py
│   │   └── pull_skyworth_permissions_xml.py
│   ├── 02_packages_and_hashes/
│   │   ├── audit_packages_and_iocs.py
│   │   ├── audit_synthient_gap_checks.py
│   │   ├── summarize_audit.py
│   │   └── verify_v2_v3_certs.py
│   ├── 03_runtime_and_network/
│   │   ├── collect_runtime_state.py
│   │   ├── deep_fs_checks.py
│   │   └── inspect_target_packages.py
│   └── 04_extraction_and_decompile/
│       ├── pull_and_decompile.py
│       ├── pull_remaining_oem_apks.py
│       ├── pull_via_exec_out.py
│       ├── scan_decompiled_iocs.py
│       └── scan_synthient_iocs.py
├── evidence/
│   ├── 01_recon/
│   ├── 02_packages_and_hashes/
│   ├── 03_runtime_and_network/
│   └── 04_extraction_and_decompile/
├── pulled_artifacts/
└── decompiled/
```

---

## İnceleme Ortamının Kurulumu ve Kullanımı

Bu analiz ortamını kendi bilgisayarınızda sıfırdan kurmak için aşağıdaki adımları izleyebilirsiniz.

### 1. Gereksinimler

* **Python:** `3.13` veya uyumlu güncel bir Python 3 sürümü (test edilen sürüm: `3.13.14`)
* **Java SDK:** `jadx` çalıştırmak için Java 11+ (test edilen sürüm: `OpenJDK 25.0.5.1`)
* **Android SDK Platform-Tools:** `adb` sunucusu için (`37.0.3-16887417`)
* **jadx:** APK kaynak kod çözümlemesi için (`1.5.7`)

### 2. Araçların Yerleştirilmesi ve Python Ortamı

1. Android SDK Platform-Tools paketini indirin. Arşiv içeriğini proje kökündeki `platform-tools/` klasörüne çıkarın.
2. `jadx` sürümünü indirin. Arşiv içeriğini proje kökündeki `jadx/` klasörüne (`jadx/bin/jadx.bat` bulunacak şekilde) çıkarın.
3. Proje kökünde sanal Python ortamını oluşturun ve `adbutils` paketini kurun.

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install adbutils
```

### 3. Cihaz Bağlantısının Kurulması

1. TV Box üzerinde **Ayarlar > Sistem > Hakkında** menüsünden derleme numarasına arka arkaya tıklayarak Geliştirici Seçeneklerini açın.
2. **USB Hata Ayıklama** veya ağ üzerinden **ADB Hata Ayıklama** seçeneğini etkinleştirin.
3. Cihazı USB veya yerel ağ (`adb connect <CIHAZ_IP>:5555`) üzerinden bağlayın.

```powershell
.\platform-tools\adb.exe connect <CIHAZ_IP>:5555
.\platform-tools\adb.exe devices
```

### 4. Analiz Scriptlerinin Çalıştırılması

Scriptler doğrudan `adb` komut satırı yerine `adbutils` (`2.12.0`) üzerinden cihazla iletişim kurar. Farklı bir cihaz incelenecekse `scripts/common/adb_helpers.py` dosyasındaki `TARGET_DEVICE_SERIAL` değerini kendi cihaz kimliğinizle güncelleyin.

```powershell
.\venv\Scripts\python.exe .\scripts\01_recon\collect_device_profile.py
.\venv\Scripts\python.exe .\scripts\02_packages_and_hashes\audit_packages_and_iocs.py
.\venv\Scripts\python.exe .\scripts\02_packages_and_hashes\audit_synthient_gap_checks.py
.\venv\Scripts\python.exe .\scripts\03_runtime_and_network\collect_runtime_state.py
.\venv\Scripts\python.exe .\scripts\04_extraction_and_decompile\pull_and_decompile.py
.\venv\Scripts\python.exe .\scripts\04_extraction_and_decompile\scan_synthient_iocs.py
```

Çalışma sonucunda üretilen ham çıktılar `evidence/` klasörüne, çekilen APK dosyaları `pulled_artifacts/` klasörüne, çözümlenen Java kaynak kodları ise `decompiled/` klasörüne kaydedilir.

---

## Referanslar ve Kullanılan Araçlar

### Tehdit İstihbaratı ve Araştırma Kaynakları

* **Google Cloud Threat Intelligence (GTIG):** [Shutting the Door on the XCPE Botnet](https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet)
* **Synthient Kamu Araştırması:** [The Internals of a Badbox Operation (Videostrong)](https://github.com/synthient/public-research/blob/main/2026/11/Videostrong/README.md)
* **xcpe-guard Yanlış Pozitif Analizi:** [xcpe-guard Issue #3 — Temiz Skyworth Digital Cihazlarda com.oemservice Yanlış Alarmı](https://github.com/burakztrk/xcpe-guard/issues/3)

### Kullanılan Araçlar ve Kütüphaneler

* **adbutils (`2.12.0`):** [openatx/adbutils](https://github.com/openatx/adbutils)
* **Android SDK Platform-Tools (`adb` `37.0.3`):** [Android Developers Platform-Tools](https://developer.android.com/tools/releases/platform-tools?hl=tr)
* **jadx (`1.5.7`):** [skylot/jadx](https://github.com/skylot/jadx)