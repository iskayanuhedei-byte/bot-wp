# Hasil pemeriksaan BagoesWP OLS Manager 0.2.7

Sumber: ZIP `BagoesWP-OLS-Manager-v0.2.6-auth-fix.zip` yang diunggah pengguna. ZIP asli tetap utuh. Kode diperbaiki di checkout cloud `/workspace/bot-wp`; GitHub sumber belum mempunyai commit saat pemeriksaan awal. Paket versi 0.2.7 tersedia di folder `releases` repositori `iskayanuhedei-byte/bot-wp`.

## Penilaian

Fondasi provisioning sudah mencakup OpenLiteSpeed, LSPHP, LSCache, Redis, OPcache, pemisahan situs, cron, verifikasi HTTP/TLS, benchmark ringan, serta rollback. Versi 0.2.6 masih memiliki bug yang dapat menggagalkan login PPK, startup database, dan ketepatan audit. Perbaikan ini mendukung pengembangan dan pengujian; kesiapan produksi serta kapasitas traffic harus dibuktikan pada VPS Ubuntu 24.04.

## Perbaikan yang dilakukan

| Masalah versi lama | Perbaikan 0.2.7 |
|---|---|
| Konversi PPK mengandalkan opsi CLI PuTTYgen Unix pada aplikasi desktop Windows | Parser PPK native v2/v3: RSA, ECDSA, Ed25519; AES/Argon2, MAC wajib, public/private key wajib cocok |
| Error pembacaan key tertentu keluar dari jalur fallback | Error dibungkus sebagai diagnosis SSH dan resource koneksi dibersihkan |
| Tes Koneksi sukses tetapi provisioning gagal karena akun Ubuntu tidak punya sudo | Tes akses root/sudo read-only; petunjuk username `ubuntu` dan perbedaan passphrase/password sudo |
| Password admin WP berada di base64 argument proses remote | Payload melalui stdin, terpisah dari password sudo termasuk NOPASSWD/cached sudo |
| Minimal satu worker per situs tetap dijalankan walau anggaran RAM terlampaui | Anggaran memasukkan 256 MiB per worker + overhead OPcache; reservation RUNNING diperiksa sebelum membuat user/database |
| `Not connected`/`disconnected` cocok dengan substring `connected` | Status Redis harus persis `Status: Connected` dan command harus sukses |
| DNS/renewal sementara gagal membuat `ssl_active=False` pada situs yang sudah HTTPS | Konfigurasi TLS existing dipertahankan; validitas sertifikat tetap diuji oleh audit wajib |
| Resume situs VERIFIED mengabaikan permintaan perubahan SSL/www/email | Early return hanya untuk konfigurasi yang sama dan SSL yang sudah aktif bila diminta |
| `innodb_buffer_pool_instances=1` tidak tersedia pada MariaDB 10.11 | Opsi tersebut dihapus dari konfigurasi yang dihasilkan |
| Retry/perubahan domain dapat berjalan saat task lain aktif | Busy guard menyeluruh dan installer lokal per worker |
| Field CSV lolos validasi dengan spasi tetapi ditolak agent | Field non-password dinormalisasi; password tetap dipertahankan persis |

Penghapusan opsi MariaDB didasarkan pada registry variabel sumber resmi 10.11.6: https://github.com/MariaDB/server/blob/mariadb-10.11.6/storage/innobase/handler/ha_innodb.cc#L19703 . Format PPK mengikuti manual PuTTY Appendix C dan diuji terhadap PuTTYgen 0.83 asli.

## Profil VPS yang diberikan

Perhitungan di bawah memakai RAM nominal penuh, bukan hasil benchmark traffic. Aplikasi memakai MemTotal VPS sebenarnya sehingga angka dapat berbeda.

| Profil | 1 situs: worker PHP/situs | 5 situs: worker PHP/situs | 10 situs: worker PHP/situs | Kapasitas awal berdasarkan anggaran RAM |
|---|---:|---:|---:|---:|
| 8 GiB / 2 vCPU | 10 | 2 | ditolak | 9 situs |
| 8 GiB / 4 vCPU | 10 | 2 | ditolak | 9 situs |
| 16 GiB / 4 vCPU | 10 | 4 | 2 | 18 situs |

Angka worker di atas adalah plafon proses menurut RAM, bukan jumlah request yang sebaiknya bersamaan pada CPU tersebut. Batas maksimum 10 job instalasi tetap berlaku dan berbeda dari jumlah situs yang dapat ditampung. Situs existing yang melampaui kapasitas tetap bisa diperbaiki, tetapi tidak mendapat status OPTIMAL. Reservation RUNNING yang ditinggalkan job terputus masih dihitung; retry domain tersebut untuk menyelesaikan atau melepaskan reservation melalui jalur gagal yang dilaporkan.

4 vCPU memberi ruang lebih besar untuk request dinamis daripada 2 vCPU dengan RAM sama. RAM 16 GiB membantu lebih banyak situs/proses/object cache, tetapi tidak menggandakan kapasitas CPU. Tema/plugin, query, visitor login, WooCommerce/cart, bot crawl, CDN, dan cache hit ratio menentukan traffic nyata. Benchmark bawaan mengukur request cache lokal dalam jumlah kecil; status OPTIMAL tidak menjanjikan angka visitor tertentu.

## Bukti pengujian

- Python 3.12: **98 tes lulus, 0 gagal, 0 dilewati**, termasuk semua tes lama yang relevan dan regresi baru.
- PuTTYgen 0.83 asli menghasilkan 20 kombinasi RSA/ECDSA tiga kurva/Ed25519 × PPK v2/v3 × terenkripsi/tanpa enkripsi; hasil public key sama setelah pembacaan native dan pemuatan Paramiko.
- Argon2id, Argon2i, Argon2d, passphrase Unicode, MAC rusak, public/private key tidak cocok, dan batas parameter KDF diuji.
- Server SSH lokal nyata menerima PPK terenkripsi RSA dan Ed25519 v2/v3 tanpa password; perubahan host key ditolak dan tidak mencoba fallback.
- Pemisahan stdin sudo diuji dengan password dikonsumsi dan tersisa; payload/password tidak masuk command atau log aplikasi.
- Kapasitas, reservation job, SSL retry, Redis health, perubahan payload, kompatibilitas MariaDB, dan kontrol UI diuji dengan mock operasi VPS.
- `pip check` dan kompilasi modul lulus. GUI Tkinter benar-benar dibuka menggunakan Xvfb; kontrol PPK dan busy guard lulus.
- Install script cloud dijalankan dan diulang; instruksi startup GUI dijalankan. Field `install_script` dan `start_skill` tersimpan dalam draft cloud, belum dipublikasikan.

Belum diuji: EXE/GUI Windows secara langsung, sshd Ubuntu pengguna, provisioning OLS/LSPHP/MariaDB/Redis pada Ubuntu 24.04, DNS/Let's Encrypt nyata, serta beban eksternal. Tes fungsi remote memakai mock agar tidak mengubah VPS atau host cloud Debian. Gerbang VPS disposable terperinci ada di `PENGUJIAN.md`.

## Cara memakai perbaikan PPK

Ekstrak ZIP versi baru ke folder baru dan jalankan `run_windows.bat` agar semua dependency runtime terpasang. Pilih PPK, username yang sesuai dengan key (Ubuntu cloud sering `ubuntu`), file key, dan passphrase jika key terenkripsi. Kosongkan password SSH saat mengetes agar fallback password tidak menyamarkan hasil PPK. Tekan Tes Koneksi; log harus menyebut PPK berhasil dan hak root/sudo siap. Password sudo hanya diperlukan jika akun tidak memakai NOPASSWD.

Jika server menolak public key yang valid, pasang pasangan public key pada `authorized_keys` akun yang benar atau periksa konfigurasi sshd; aplikasi tidak dapat mengubah izin login sebelum mempunyai akses. Jangan kirim private key/passphrase di chat. Untuk EXE, jalankan `build_windows.bat` di Windows dan uji hasilnya sebelum distribusi.
