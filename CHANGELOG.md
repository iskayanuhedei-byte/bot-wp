# Changelog

## 0.2.7

- Perbaikan PPK Windows: parser native v2/v3, MAC wajib, AES/Argon2, dan RSA/ECDSA/Ed25519; PuTTYgen tidak diperlukan saat login.
- Tes key PuTTYgen asli, autentikasi SSH lokal tanpa password, dan host key mismatch yang menghentikan fallback.
- Pemisahan payload WordPress dan password sudo melalui framing stdin, termasuk NOPASSWD/cached sudo; kredensial tidak berada dalam argv.
- Tes Koneksi memeriksa izin sudo dan menjelaskan perbedaan passphrase key/password sudo.
- Anggaran PHP memasukkan OPcache, memory_limit 256M, dan reservation situs sebelum provisioning paralel.
- Status Redis harus persis Connected; Not connected/disconnected tidak lolos audit.
- Retry DNS/certbot mempertahankan konfigurasi TLS existing. Perubahan SSL/www/email pada situs terverifikasi tetap diterapkan.
- Hapus innodb_buffer_pool_instances yang tidak tersedia pada MariaDB 10.11 Ubuntu 24.04.
- Kunci Retry dan mutasi domain selama task aktif; normalisasi field CSV sesuai payload agent.

## 0.2.6

- Menambahkan mode autentikasi `Otomatis` yang mencoba private key yang terdeteksi, lalu Password SSH, lalu SSH Agent/Pageant.
- Metode PPK/OpenSSH kini tetap dapat memakai Password SSH sebagai fallback jika key lokal gagal dikonversi/dibaca atau key ditolak server.
- Metode Password dapat fallback ke private key yang tersedia dan SSH Agent/Pageant.
- Deteksi PPK tidak hanya berdasarkan ekstensi `.ppk`, tetapi juga header isi file.
- Konversi PPK mencoba `private-openssh-new` lalu `private-openssh`, memaksa hasil sementara tanpa passphrase, dan menampilkan detail kegagalan PuTTYgen tanpa membocorkan passphrase.
- Pencarian `puttygen.exe` diperluas ke PATH, Program Files, LOCALAPPDATA, folder aplikasi, dan folder `tools`.
- Tes koneksi melaporkan metode autentikasi yang benar-benar berhasil.
- Menambah gerbang tes lokal dari 49 menjadi 53 tes tanpa mengurangi provisioning, audit, tuning, cleanup, maupun uninstall.

## 0.2.5

- Mengaktifkan kolom `Key passphrase` untuk PPK terenkripsi, sehingga key yang bekerja di Termius dapat dipakai tanpa mengekspor key tanpa proteksi.
- Mengirim passphrase ke PuTTYgen melalui file sementara berizin terbatas, bukan melalui argumen command line atau log.
- Menambahkan pemilih `puttygen.exe` ke GUI dan otomatis memilih mode PPK/OpenSSH berdasarkan ekstensi private key.
- Memisahkan pesan PPK terenkripsi tanpa passphrase, passphrase salah, PuTTYgen lama, private key ditolak, password ditolak, dan metode Password SSH yang dinonaktifkan server.
- Menambah gerbang tes lokal dari 45 menjadi 49 tes tanpa mengurangi provisioning, audit, tuning, cleanup, maupun uninstall.

## 0.2.4

- Memperbaiki permalink WordPress yang 404 walaupun struktur `/%postname%/` sudah tersimpan, dengan menulis blok rewrite WordPress yang kompatibel dengan `autoLoadHtaccess` OLS secara idempoten.
- Memindahkan reload OLS ke setelah aturan redirect HTTPS ditulis, sehingga pemeriksaan redirect tidak lagi berlomba dengan konfigurasi lama.
- Menambahkan status HTTP dan pesan error probe permalink ke laporan audit.
- Pesan kegagalan kini hanya menyebut pemeriksaan wajib yang benar-benar gagal; flag informasi seperti `ssl_pending=false` dan agregat `mandatory_ok=false` tidak lagi ikut ditampilkan sebagai penyebab.
- Menambah gerbang tes lokal dari 42 menjadi 45 tes.

## 0.2.3

- Memperbaiki kegagalan config-test akibat document root vhost `Example` bawaan OLS masih dimiliki UID/GID root.
- Mendeteksi user/group proses OpenLiteSpeed dari konfigurasi utama dan menormalkan ownership hanya pada `/usr/local/lsws/Example/html`.
- Menoleransi secara terbatas warning UID/GID vhost Example yang dikenal jika tidak terdapat `ERROR` atau `FATAL`; kesalahan konfigurasi lain tetap fail-closed.
- Menambah gerbang tes lokal dari 39 menjadi 42 tes.

## 0.2.2

- Memperbaiki bootstrap yang mencoba `systemctl enable` langsung pada alias `lsws.service`; aplikasi kini mendeteksi dan mengaktifkan unit kanonis OpenLiteSpeed lalu memverifikasi alias aktif.
- Menambahkan uninstall satu atau beberapa domain melalui pilihan tabel maupun input domain manual.
- Menambahkan uninstall global seluruh website, database/user situs, vhost, sertifikat, timer, tuning, dan konfigurasi BagoesWP dengan konfirmasi ketik.
- Membatasi penghapusan pada state, user, database, vhost, dan direktori yang identitas deterministiknya cocok dengan domain.
- Memulihkan state apabila pelepasan konfigurasi OLS gagal, serta mempertahankan paket server bersama pada uninstall global.
- Menambah gerbang tes lokal dari 31 menjadi 39 tes.

## 0.2.1

- Memperbaiki bootstrap yang sebelumnya hanya memasang repository LiteSpeed ketika paket `openlitespeed` tidak ditemukan.
- Selalu menyegarkan repository resmi LiteSpeed sebelum memilih paket OpenLiteSpeed/LSPHP dan mengulang satu kali jika metadata inti belum lengkap.
- Mengikuti packaging LSPHP aktual: nama paket ekstensi terpisah bersifat opsional, tetapi modul runtime WordPress tetap wajib lulus.
- Menambahkan perbaikan otomatis ekstensi runtime serta syarat pemrosesan gambar melalui GD atau Imagick.
- Menambah gerbang tes lokal dari 27 menjadi 31 tes tanpa mengurangi fitur performa versi 0.2.0.

## 0.2.0

- Menambahkan status `INSTALLED`, `VERIFIED`, dan `OPTIMAL` yang terpisah.
- Menambahkan deteksi RAM tersedia, swap, load, vCPU, dan penggunaan disk.
- Membatasi pembagian resource agar total budget tidak melewati RAM yang didukung.
- Menambahkan OPcache tuning per website, browser cache 180 hari, dan pemeriksaan compression.
- Mengganti pemeriksaan HTTPS insecure dengan validasi CA, hostname bare/`www`, dan masa berlaku.
- Menambahkan tes permalink nyata jika website memiliki post publik.
- Menambahkan benchmark per website dan benchmark gabungan semua vhost.
- Menambahkan tuning PHP adaptif satu langkah dengan config-test dan rollback saat skor memburuk.
- Menambahkan capacity gate agar VPS yang terlalu kecil tidak diberi status `OPTIMAL`.
- Menambahkan monitor systemd per jam dan laporan JSON.
- Menambahkan pembersihan expired transient, spam lebih dari 30 hari, serta optimasi database mingguan.
- Memperbarui launcher, builder, dan diagnosis Windows ke v0.2.0.
- Menambah gerbang tes lokal dari 14 menjadi 27 tes.

## 0.1.1

- Memperbaiki launcher dan builder Windows agar error terlihat dan dicatat.
- Menambahkan diagnosis Windows dan crash log aplikasi.

## 0.1.0

- Rilis awal bulk installer WordPress untuk OpenLiteSpeed.
