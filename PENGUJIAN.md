# Gerbang Pengujian BagoesWP

Versi 0.2.7 memiliki 98 tes otomatis lokal. Run cloud dengan PuTTYgen 0.83: 98 lulus, 0 gagal, 0 dilewati. Angka ini tidak menggantikan gerbang VPS disposable di bawah.

## Yang sudah diuji otomatis

- Validasi dan normalisasi domain, duplikat, CSV, locale, email, dan password.
- Batas concurrency tidak pernah melebihi 10 job.
- Payload shell-safe dan disamarkan dari log koneksi.
- Perhitungan resource serta kesamaan `maxConns` dan `PHP_LSAPI_CHILDREN`.
- Parser RAM/swap, percentile benchmark, ambang performa, dan tuning satu langkah yang dibatasi baseline aman.
- Browser-cache config dan validasi SSL yang tidak memakai mode insecure.
- Konfigurasi manager deterministik dan database grant tidak global.
- Pembersihan file hanya berlangsung di root cache/log yang diizinkan.
- Modul Python dapat dikompilasi tanpa syntax error.
- Status akhir hanya dipromosikan ke `OPTIMAL` dari hasil audit yang eksplisit.
- Alias systemd OpenLiteSpeed diubah ke unit kanonis sebelum `enable`, kemudian alias tetap diuji aktif.
- Payload uninstall dinormalisasi, identitas state harus cocok, penghapusan direktori dibatasi allowlist, dan state dipulihkan jika config-test OLS gagal.
- Uninstall global tidak pernah menjalankan purge paket server bersama.
- User/group proses OLS dibaca dari konfigurasi utama sebelum ownership vhost Example diperbaiki.
- Hanya warning UID/GID vhost Example yang dikenal dapat ditoleransi; adanya `ERROR` atau `FATAL` tetap menolak config-test.
- Aturan rewrite WordPress dibuat idempoten, reload SSL terjadi setelah redirect ditulis, dan laporan kegagalan hanya memuat pemeriksaan wajib.
- PPK v2/v3 native: RSA, ECDSA tiga kurva, Ed25519, terenkripsi/tanpa enkripsi; interoperabilitas dengan PuTTYgen asli dan semua flavor Argon2. Passphrase tidak berada di command line. MAC, kesesuaian key, parameter KDF, cleanup gagal, dan fallback tetap diuji.
- Login SSH lokal nyata menerima PPK v2/v3 RSA/Ed25519 terenkripsi tanpa password; host key mismatch menghentikan fallback.
- Payload WordPress memakai stdin, dengan pemisahan password sudo yang diuji untuk password dikonsumsi maupun NOPASSWD/cached.
- Admission menghitung situs RUNNING, worker PHP, dan overhead OPcache; melebihi kapasitas ditolak sebelum resource server dibuat.
- Redis disconnected/Not connected tidak lolos, TLS existing dipertahankan saat probe/renewal gagal, dan perubahan SSL/www/email tidak dilewati resume.
- Konfigurasi MariaDB tidak memuat opsi innodb_buffer_pool_instances yang dihapus pada 10.11.
- Retry dan perubahan domain dikunci saat task berjalan, dan field validasi lokal sesuai payload remote.

## Yang wajib diuji pada VPS disposable

Kode tidak boleh disebut siap produksi hanya dari mock lokal. Gunakan Ubuntu 24.04 baru, buat snapshot, lalu jalankan gerbang berikut:

1. Pasang satu domain canary terlebih dahulu.
2. Pastikan status `OPTIMAL`, `VERIFIED`, atau `INSTALLED_PENDING_SSL`, bukan sekadar proses selesai.
3. Periksa laporan: WordPress core, plugin LSCache, Redis, ownership non-root, database, permalink, browser cache, HTTP, dan cache HIT wajib lulus.
4. Ulangi instalasi domain yang sama untuk membuktikan resume/idempotensi.
5. Putuskan DNS pada satu domain uji; instalasi harus selesai sebagai `INSTALLED_PENDING_SSL`, sementara domain lain tetap berjalan.
6. Masukkan satu domain dengan data salah; hanya domain itu yang boleh gagal.
7. Pulihkan snapshot, kemudian jalankan 10 domain sekaligus.
8. Setelah retune, audit akhir seluruh domain harus tetap lulus.
9. Bandingkan benchmark bawaan dengan uji beban eksternal bertahap dan pantau RAM, swap, CPU, MariaDB slow log, error log OLS, serta cache hit ratio.
10. Baru pindahkan konfigurasi ke server produksi setelah hasil uji beban memenuhi target nyata Anda.
11. Uji uninstall satu domain dari batch, pastikan domain lain tetap aktif dan konfigurasi OLS tetap lolos.
12. Uji uninstall global setelah snapshot dan pastikan semua resource BagoesWP hilang sementara paket server bersama tetap tersedia.

## Simulasi kegagalan yang wajib

- Buat sertifikat hostname salah; audit harus menolak validasi SSL.
- Nonaktifkan Redis; status tidak boleh `VERIFIED` atau `OPTIMAL`.
- Paksa konfigurasi OLS invalid; config-test harus menggagalkan perubahan dan rollback.
- Tekan RAM sampai swap bertambah saat benchmark; status tidak boleh `OPTIMAL` dan tuning hanya boleh turun satu langkah.
- Buat kandidat tuning lebih lambat; laporan harus menunjukkan `rolled_back: true`.

## Kriteria berhenti

Jangan lanjut ke produksi jika ada konfigurasi OLS yang gagal `openlitespeed -t`, service tidak aktif, document root dimiliki root, Redis terputus, atau respons kedua tidak menghasilkan cache HIT. Aplikasi memperlakukan kondisi wajib tersebut sebagai kegagalan dan menyimpan tahapnya untuk retry.

## Hasil cloud versi 0.2.7

- Python 3.12, Paramiko 5.0.0, cryptography 50.0.2, argon2-cffi 25.1.0; `pip check` lulus.
- Suite 98 tes lulus tanpa skip saat `BAGOESWP_TEST_PUTTYGEN` disediakan. Subtest mencakup 20 kombinasi key/version/encryption keluaran PuTTYgen, tiga flavor Argon2, dan autentikasi SSH lokal nyata.
- GUI Tkinter dibuka pada Xvfb; inisialisasi, kontrol PPK, dan busy guard lulus.
- Install script diuji dan diulang dengan dependensi yang sudah tersedia. `install_script` dan `start_skill` disimpan sebagai draft konfigurasi cloud; publikasi belum dilakukan.
- Build Windows EXE, provisioning VPS Ubuntu 24.04, issuance DNS/SSL, server OLS/MariaDB/Redis, dan uji beban eksternal **belum dijalankan**. Tetap jalankan gerbang VPS disposable di atas.
