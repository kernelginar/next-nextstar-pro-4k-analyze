Öncelikle son kullanıcıların root veya bilgisayar gerektirmeden kendi Android TV kutularını kontrol edebilmesi için geliştirdiğiniz xcpe-guard aracı için teşekkürler. 

Aracın tespit ve engelleme mantığını Türkiye ve Avrupa pazarındaki yaygın Android TV kutuları üzerinde incelediğimizde, gerçek Skyworth Digital üretimi olan Google sertifikalı temiz cihazları (Next Start 4K, Next Start Pro 4K, Strong Leap-S3, RockTek G2/GX1 vb.) etkileyen önemli bir Hatalı Tespit (False Positive) durumu belirledik. 

1. Sorunun Kaynağı: com.oemservice Paket Adı Çakışması (Skyworth vs. Videostrong)
Google GTIG ve Synthient raporlarında belirtildiği üzere Videostrong, geliştirdiği arka kapıyı gizlemek için meşru com.oemservice (etiketi xcpe / x.cpe) paket adını kullanmış ve hatta ortak BSP/tedarik zinciri geçmişi (MECOOL vb.) nedeniyle bazı zararlı örneklerde Skyworth Digital sertifika imzası görülmüştür. 
Ancak gerçek ve temiz Skyworth Digital ODM üretimi lisanslı kutularda (C3.x yapı numaralı yazılımlar):
•	com.oemservice (etiketi xcpe), standart Amlogic/Skyworth BSP imajında yer alan yaklaşık 21 KB boyutunda tamamen yasal ve zararsız bir sistem uygulamasıdır. 
•	Yalnızca ilk kurulumda (BOOT_COMPLETED) /oem klasöründeki ön yüklü operatör APK'larını kurmak ve standart OTA servisini tetiklemek için çalışan basit bir BroadcastReceiver içerir. 
•	İçerisinde kesinlikle MQTT istemcisi (mqtt.szbboys.com, *.anyevonline.com), shell komut yürütücüsü veya AccessibilityKeyDetector kancası bulunmaz ve Google Play Protect'i kapatmaz (package_verifier_user_consent açık kalır). 
(Skyworth ve Videostrong ayrımını gösteren mimari şema ektedir).
2. xcpe-guard İçindeki Mevcut Davranış ve Yan Etkiler
Şu anda xcpe-guard, /oem altındaki 7 adet zararlı SHA-256 özetini "sadece raporlananlar" (what it only reports) kısmında kontrol etmekte, ancak "devre dışı bırakılanlar" (what it switches off) aşamasında SHA-256 veya dosya boyutu doğrulaması yapmadan doğrudan paket adına bakarak pm disable-user com.oemservice komutunu çalıştırmaktadır: 
1.	com.oemservice Yanlış Alarmı: Temiz bir Next Start 4K veya Strong Leap-S3 kullanıcısı aracı çalıştırdığında, araç 21 KB'lık masum Skyworth sistem servisini görüp kapatmakta ve kullanıcıya "XCPE arka kapısı bulundu ve kapatıldı" uyarısı vermektedir. Bu paketin kapatılması cihazı bozmasa da, temiz cihaz sahiplerinde gereksiz paniğe ve cihazlarının botnet'e dahil olduğu yanılgısına yol açmaktadır. 
2.	com.oem.qa (BoxFactoryTest) Kapatılması: Google'ın resmi IoC listesinde yer almayan com.oem.qa paketi birçok Amlogic/Skyworth referans kartında standart fabrika donanım test uygulamasıdır; doğrudan şüpheli işaretlenip kapatılması temiz kutularda yanlış uyarı üretmektedir. 
3.	com.ota.service Çakışma Riski: Videostrong'un HiddenView modülü bu paket adını kullansa da, meşru bazı AOSP/STB üreticileri kendi resmi yazılım güncelleme istemcilerini com.ota.service olarak adlandırmaktadır. Hash veya ikincil IoC kontrolü yapmadan bu paketi kapatmak cihazın resmi OTA güncellemelerini durdurabilir. 
4.	Özel DNS (Private DNS) Ayarının Kapatılması: Ev ağında AdGuard Home veya Pi-hole kullanmayan standart kullanıcılar için Android'in Private DNS: Automatic ayarının doğrudan off konumuna çekilmesi şifreli DNS güvenliğini düşürmektedir. 
3. Çözüm Önerisi
com.oemservice (veya com.ota.service / com.oem.qa) paketlerini "zararlı" olarak işaretleyip pm disable-user ile devre dışı bırakmadan önce adbd üzerinden doğrulama eklenmesini öneriyoruz:
•	Yöntem A (SHA-256 ve Dosya Boyutu Kontrolü): pm path com.oemservice komutuyla APK yolu alınıp SHA-256 özeti (Google/Synthient zararlı hash listesiyle) veya dosya boyutu (stat -c %s) kontrol edilmelidir. Temiz Skyworth paketi ~21 KB iken, Videostrong botnet APK'sı çok daha büyüktür ve bilinen zararlı SHA-256 özetlerine sahiptir.
•	Yöntem B (Bileşik Gösterge / Compound IoC Kontrolü): com.oemservice paketi yalnızca cihazda aşağıdaki kesin enfeksiyon göstergelerinden en az biri daha varsa "Arka Kapı" olarak işaretlenip kapatılmalıdır:
o	Kesin zararlı paketlerden birinin varlığı (x.cpe, com.abc.nexus, com.vs.grass, com.android.system.ntp, com.android.sso.auth.handler, com.gaganode*, com.newtv.cboxtv)
o	package_verifier_user_consent == -1 (Play Protect'in zorla kapatılmış olması)
o	Erişilebilirlik servislerinde AccessibilityKeyDetector kancasının bulunması
o	Zararlı native kütüphanelerin (libseccomp_guard.so, libfleetshare.so vb.) veya persist.networkstack.* özelliklerinin varlığı
o	/oem altındaki APK'nın zararlı SHA-256 listesiyle eşleşmesi 
•	Arayüz Bilgilendirmesi: Eğer cihazda hiçbir ikincil IoC yoksa ve com.oemservice zararsız 21 KB'lık Skyworth sürümü ise, kullanıcıya alarm vermek yerine "Temiz Skyworth Sistem Servisi (Güvenli / Doğrulandı)" şeklinde bilgi gösterilmesi yanlış anlaşılmaları tamamen önleyecektir.