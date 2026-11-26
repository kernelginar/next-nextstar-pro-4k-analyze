# Next NextStar 4K TV Box — XCPE Botnet Adli İnceleme Raporu

## 1. Yönetici Özeti
**Hedef Cihaz:** Next NextStar 4K TV Box (`Next` / `UHD Google TV STB`, ADB Seri: `90094381518171`)
**Üretici / Yazılım:** `SkyworthDigital`, Android 14 (`Next/HPR314-Next/RMQ:14/UTT1.250214.001/C1.0.8_20260520:user/release-keys`), Güvenlik Yaması `2026-05-05`

### Temel Sonuç
Cihazda **aktif bir XCPE botnet enfeksiyonu, çalışan MQTT C2 bağlantısı, Play Protect müdahalesi (`package_verifier_user_consent = -1`) veya affiliate (proxy/ad-fraud) modülü tespit edilmemiştir**.

Bununla birlikte, cihazın sistem imajı içinde **doğrudan XCPE mimarisiyle örtüşen yerleşik bir kalıcılık/sessiz yükleme taslağı (`stub`)** bulunmaktadır:
* **`com.oemservice`** (`/system/priv-app/app_xcpe_preset/app_xcpe_preset.apk`, `uid=1000` / `android.uid.system`), **SkyworthDigital platform anahtarıyla** imzalanmıştır ve `/system/etc/permissions/privapp-permissions-SkyworthDigital.xml` içinde `READ_FRAME_BUFFER`, `INJECT_EVENTS`, `WRITE_SECURE_SETTINGS`, `GRANT_RUNTIME_PERMISSIONS`, `DELETE_PACKAGES`, `INSTALL_SELF_UPDATES` dahil **51 ayrıcalıklı yetkiyle** açıkça yetkilendirilmiştir.
* Bu paket içindeki `x.cpe.receiver.BootReceiver` ve `x.cpe.UpgradeService`, şu an `/oem` kök dizininde eşleşen bir `com.oemservice` APK'sı bulunmadığı için **uykuda (dormant)** durumdadır ve yalnızca yerel `/oem` APK yükseltme/geri yükleme mekanizmasını içerir; C2/MQTT veya gözetleme kodu barındırmaz.

---

## 2. Doğrulanmış Kanıtlar

### A. `com.oemservice` (`app_xcpe_preset.apk`) Statik Analizi
* **Yol & SHA256:** `/system/priv-app/app_xcpe_preset/app_xcpe_preset.apk` — `7316469fd5b9fa633d9474a14b72716b9ceb4bbf656725ab79409da608eda2be` (25.155 bayt)
* **İmza:** `EMAILADDRESS=skydigital@skyworth.com, CN=skydigital, OU=SKYWORTH, O=SKYWORTH, L=ShenZhen, ST=GuangDong, C=CN` (`SHA256: 12:BF:50:A0:3F:1E:D9:C9:1A:6C:0A:E0:B7:8D:CA:88:2C:70:05:88:5A:17:8A:ED:D5:49:CD:A2:7F:DE:60:1C`)
* **Kod Davranışı (`decompiled/system_priv_apps__app_xcpe_preset`):**
  1. `x.cpe.receiver.BootReceiver` (`BOOT_COMPLETED`, `priority=1000`): `persist.sys.cpe.show_log` sistem özelliğini okur, `new File("oem")` (`/oem`) altındaki dizin olmayan dosyaları tarar, paket adı `com.oemservice` olan bir APK bulursa `x.cpe.UpgradeService` ön plan servisini başlatır.
  2. `x.cpe.UpgradeService`: `"New Message"` / `"You've received new messages."` sahte bildirimiyle ön plan servisi açar ve `PackageInstaller` üzerinden verilen APK'yı `android.uid.system` yetkisiyle sessizce kurar.
* **Neden Videostrong/XCPE ile İlişkili?**
  * Google Threat Intelligence raporundaki `x.cpe` / `com.oemservice` paket adı, `android.uid.system` yetkisi, `/oem/` üzerinden kendi kendini geri yükleme davranışı ve `privapp-permissions-SkyworthDigital.xml` dosyasındaki `READ_FRAME_BUFFER` + `INJECT_EVENTS` + `WRITE_SECURE_SETTINGS` izin seti birebir örtüşmektedir.
  * Ek olarak sistem `build.prop` dosyasında `import /oem/oem.prop ro.mecool.device.model` satırı ve sistemde `com.sdt.mecoolrcupair` (`SdtRcuPair.apk`) paketi yer almaktadır; `BoxFactoryTest_preset.apk` (`com.oem.qa`) da aynı `persist.sys.cpe.show_log` + `/oem` tarayıcı şablonunu kullanmaktadır. Bu bulgular SkyworthDigital ile Videostrong/Mecool ODM altyapısı arasındaki ortak kod/şablon mirasını göstermektedir.

### B. IOC Eşleştirme ve Çalışma Zamanı Kontrolleri
* **143/143 Yüklü APK SHA256 Taraması:** `core_malware_samples.md` ve `affiliate_malware.md` içindeki bilinen zararlı hash'lerle **0 eşleşme**; paket adı eşleşmesi yalnızca **1** (`com.oemservice`). `com.abc.nexus`, `com.vs.grass`, `com.newtv.cboxtv`, `com.ota.service`, `com.android.sso.auth.handler` cihazda **yok**.
* **15 Decompile Edilmiş APK Üzerinde 169 Ağ IOC + Davranış Taraması (`static_ioc_scan.json`):** `szbboys[.]com`, `anyevonline[.]com`, `intermedia-arts[.]tv`, `yokatvonline[.]com`, `219.134.163.210/211`, `23.94.49.57`, `38.145.197.135` ve tüm affiliate alan adları için **0 eşleşme**.
* **Ağ ve Süreç Durumu:** `netstat` / `/proc/net/tcp*` yalnızca standart yerel dinleme portlarını (`5555` adbd, `8008/8009/8443` Google Cast `AndroidMediaShell`, `6466/6467` `AtvRemoteService`) göstermektedir.
* **Play Protect & Verified Boot:** `package_verifier_user_consent=1`, `ro.boot.verifiedbootstate=green`, `ro.boot.veritymode=enforcing`, `ro.boot.flash.locked=1`, `/oem` bölümü salt-okunur (`ro`) ve SHA-256 doğrulamalı (`dm-19`).

### C. Diğer İncelenen OEM, `/oem/app` ve Üçüncü Taraf Uygulamalar
* `/oem/app/SdtBackUpAppManager.apk` (`com.sdt.backupappmanger`, `uid=1000`), `/oem/app/com.next.roket.apk` (`com.next.roket`), `/oem/app/JetTV.apk` + güncellenmiş `/data/app/.../base.apk` (`com.jettv.player`), `/oem/app/NextIPTV.apk` (`com.next.iptv`), `SdtUpdate`, `SdtProductTest`, `SdtDeviceInfo`, `SdtGlobalKeyHandler`, `SdtRcuPair`, `SdtFrontPanelLedsService`, `SdtGtvPartnerConfig`, `RtkPartnerInterface` ve `BoxFactoryTest_preset` statik olarak incelendi; hiçbirinde XCPE arka kapısı veya affiliate proxy/ad-fraud SDK'sı bulunmadı.
* `/sdcard/Download/` klasöründe kullanıcı tarafından indirilmiş ancak kurulmamış iki APK (`inat-box-update-v14.apk`, `inat-box-v14-inattvproapkindir-tr (1).apk`) görüldü.

---

## 3. Güvenlik Değerlendirmesi ve Öneriler
1. **Mevcut Durum:** Cihaz şu an aktif olarak XCPE botnetine bağlı değildir; `com.oemservice` yalnızca `/oem` tabanlı boş/uykuda kalıcılık taslağı olarak mevcuttur ve AVB/dm-verity (`/oem` read-only) kilitli önyükleyici nedeniyle üçüncü taraflarca `/oem` dizinine APK yazılamaz.
2. **Artık Risk:** `com.oemservice` (`x.cpe`) paketinin **51 kritik ayrıcalıklı izinle** (`READ_FRAME_BUFFER`, `INJECT_EVENTS`, `WRITE_SECURE_SETTINGS`, `INSTALL_PACKAGE_UPDATES`) imzalı sistem imajında tutulması gereksiz ve yüksek riskli bir tedarik zinciri yüzeyidir; yetkili bir OTA/vendor güncellemesiyle `/oem/` altına `com.oemservice` APK'sı konursa sessiz sistem yetkili kurulum tetiklenebilir.
3. **Önerilen Önlem (ADB üzerinden kullanıcı için zararsız devre dışı bırakma):** Kaldırılamayan bu sistem uygulamasının boot tetikleyicisini kapatmak için istenirse `pm disable-user --user 0 com.oemservice` uygulanabilir; ayrıca `JetTV`/`NextIPTV` gibi kullanılmayan `/oem/app` uygulamalarının zaten devre dışı tutulduğu görülmüştür.
