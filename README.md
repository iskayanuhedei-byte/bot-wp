# BagoesWP OLS Manager

[Unduh paket v0.2.7](https://github.com/iskayanuhedei-byte/bot-wp/raw/refs/heads/main/releases/BagoesWP-OLS-Manager-v0.2.7-ppk-performance-fix.zip). Ekstrak ke folder baru dan jalankan `run_windows.bat`.

Aplikasi desktop Windows untuk memasang dan memverifikasi banyak WordPress pada satu VPS Ubuntu 24.04 dengan OpenLiteSpeed, LSPHP 8.3, MariaDB, Redis, LiteSpeed Cache, SSL, system cron, dan pembersihan disk otomatis.

## Status versi

Versi `0.2.7` memperbaiki login PPK di Windows dengan pembacaan native PPK v2/v3 (RSA, ECDSA, Ed25519), tanpa ketergantungan pada perintah PuTTYgen. Key terenkripsi memakai AES/Argon2 sesuai format PuTTY; MAC dan kecocokan public/private key wajib valid. Versi ini juga membatasi provisioning sesuai anggaran PHP/OPcache, memperbaiki audit Redis dan retry SSL, menghapus opsi MariaDB yang sudah tidak didukung, mengunci aksi UI saat proses berjalan, dan mengirim kredensial WordPress melalui stdin.

Jangan gunakan pertama kali pada server produksi yang berisi website penting. Uji pada VPS Ubuntu 24.04 baru dan buat snapshot provider sebelum menjalankan versi awal.

## Fitur utama

- Impor banyak domain melalui CSV atau tempel data massal.
- Maksimal 10 instalasi domain aktif bersamaan.
- SSH menggunakan mode Otomatis, password, private key OpenSSH, PPK native, atau SSH Agent/Pageant; kredensial lain yang terisi dapat dipakai sebagai fallback.
- Instalasi stack satu kali dan provisioning WordPress per domain.
- Linux user, database, database user, PHP socket, cache, dan log terpisah.
- Pembagian PHP worker berdasarkan RAM dan jumlah website, dengan overhead OPcache per kelompok proses. Jumlah worker OLS mempertimbangkan vCPU. Situs baru yang melampaui kapasitas RAM ditolak sebelum user/database dibuat, termasuk saat beberapa job berjalan bersamaan.
- Deteksi RAM tersedia, swap total/terpakai, load, vCPU, serta kapasitas disk.
- `Max Connections` selalu disamakan dengan `PHP_LSAPI_CHILDREN`.
- WP-CLI dengan password melalui stdin agar tidak masuk riwayat shell.
- LiteSpeed Cache, Redis Object Cache, OPcache, system WP-Cron, dan batas revisi.
- SSL Let's Encrypt bersifat pending jika DNS belum siap.
- Browser cache aset statis 180 hari dan compression OLS.
- Verifikasi WordPress, permalink, PHP, database, Redis, LSCache `MISS -> HIT`, HTTP, redirect HTTPS, serta sertifikat tanpa melewati validasi CA/hostname.
- Benchmark lokal ringan dengan concurrency terbatas, p50/p95, RPS, error, cache-hit, CPU, RAM, dan pertumbuhan swap.
- Tuning adaptif maksimal satu langkah per audit; kandidat yang memperburuk skor dibatalkan dan konfigurasi lama dipulihkan.
- Deteksi Cloudflare dan `CF-Cache-Status` tanpa membutuhkan token API.
- Monitor systemd per jam dan laporan kesehatan JSON.
- Resume aman, retry domain gagal, backup konfigurasi, config-test, dan rollback OLS.
- Uninstall satu/beberapa domain berdasarkan pilihan atau input manual; hanya resource dengan identitas BagoesWP yang dapat dihapus.
- Uninstall global seluruh situs dan konfigurasi/otomasi BagoesWP dengan konfirmasi `HAPUS SEMUA`. Paket OLS, MariaDB, dan Redis dipertahankan agar data server lain tidak ikut terhapus.
- Disk guard bertingkat mulai 40%, expired transient, spam lama, optimasi database mingguan, laporan teks/JSON, serta pembersihan berbasis allowlist.

## Menjalankan dari source di Windows

1. Instal Python 3.11–3.13 64-bit.
2. Ekstrak folder ini.
3. Klik dua kali `run_windows.bat`.
4. Untuk membuat `.exe`, klik dua kali `build_windows.bat`.

Hasil build berada di `dist\BagoesWP-OLS-Manager.exe`.

`build_windows.bat` versi 0.2.7 langsung membuka aplikasi setelah build berhasil. Jika sebuah proses gagal, jendela tidak langsung tertutup dan laporan disimpan di folder `logs`. Jalankan `diagnose_windows.bat` lalu kirim `logs\diagnostic.txt` apabila aplikasi tetap tidak muncul.

## Format CSV

Gunakan header berikut:

```csv
domain,title,admin_user,admin_email,admin_password,locale,ssl,www
example.com,Example Site,siteadmin,admin@example.com,GantiPasswordKuat123!,en_US,true,true
```

- `ssl`: `true` atau `false`.
- `www`: memasukkan `www.domain` ke listener dan sertifikat.
- Domain tanpa DNS aktif tetap dapat dipasang, tetapi SSL berstatus pending.
- Password tidak disimpan ke file konfigurasi aplikasi.

Contoh tersedia pada `examples/domains-template.csv`.

## Definisi status

- `PENDING`: belum diproses.
- `RUNNING`: sedang dipasang.
- `INSTALLED`: komponen WordPress dan konfigurasi OLS sudah terpasang, tetapi audit wajib belum selesai.
- `INSTALLED_PENDING_SSL`: pemeriksaan lokal lulus, tetapi DNS/SSL belum siap.
- `VERIFIED`: seluruh pemeriksaan wajib lulus, tetapi satu atau beberapa ambang performa belum tercapai.
- `OPTIMAL`: pemeriksaan wajib dan benchmark memenuhi semua ambang v0.2.7.
- `FAILED`: ada tahap wajib yang gagal; laporan menyimpan tahap dan pesan.
- `CANCELLED`: job belum dimulai ketika proses dihentikan.

## Batas versi awal

- Target server hanya Ubuntu 24.04 baru atau server yang sudah memakai OpenLiteSpeed tanpa web server lain pada port 80/443.
- Minimal RAM 2 GB. Kapasitas awal jumlah situs dihitung dari resource aktual. Situs baru yang melampaui anggaran PHP ditolak; situs existing masih bisa diperbaiki, tetapi tidak mendapat status `OPTIMAL` jika kapasitas terlampaui. Perhitungan ini estimasi, bukan batas RSS keras atau jaminan traffic.
- Cloudflare API belum mengubah DNS atau trusted-proxy IP otomatis; pemeriksaan saat ini hanya mendeteksi kesiapan/proxy dan header cache.
- Benchmark bawaan sengaja ringan dan dijalankan dari VPS. Untuk target traffic tertentu, gerbang uji beban eksternal pada VPS disposable tetap wajib.
- Pengujian lokal menggunakan unit test dan pemeriksaan sintaks. Verifikasi produksi tetap harus dilakukan pada VPS uji yang benar-benar bersih.
- PPK v2/v3 dibaca langsung; tidak perlu memasang `puttygen.exe`. Key RSA, ECDSA, dan Ed25519 didukung. DSA lama tidak didukung oleh Paramiko 5; gunakan key modern.
- PPK terenkripsi memakai kolom `Key passphrase`; passphrase tidak dikirim ke command line atau disimpan dalam file passphrase. Hasil OpenSSH sementara dibuat dengan izin terbatas dan dihapus saat koneksi ditutup atau konversi gagal. Parameter Argon2 yang terlalu besar ditolak sebelum alokasi.
- Host key SSH dipercaya pada koneksi pertama lalu disimpan. Perubahan host key pada koneksi berikutnya akan ditolak.

Lihat `PENGUJIAN.md` sebelum uji VPS pertama.

## Prinsip keselamatan

- Tidak menghapus uploads, tema, plugin, database, atau backup terakhir.
- Tidak menjalankan penghapusan rekursif di lokasi yang tidak masuk allowlist.
- Database user hanya mendapat hak pada database domainnya sendiri.
- Konfigurasi OLS ditulis ke include terkelola, divalidasi, lalu diterapkan secara atomik.
- Konfigurasi lama dicadangkan sebelum setiap perubahan.

## Ambang `OPTIMAL` v0.2.7

- p95 respons cache lokal maksimal 800 ms.
- Error request dan pertumbuhan swap selama tes harus 0.
- Cache hit minimal 90%.
- Peak CPU dan RAM maksimal 90%.
- Browser cache, compression, serta seluruh pemeriksaan wajib harus lulus.
- Jumlah situs tidak boleh melewati kapasitas PHP aman dari pembagian RAM.

Ambang ini adalah gerbang dasar, bukan janji jumlah visitor tertentu. Tema, plugin, query, lokasi pengunjung, CDN, dan spesifikasi VPS tetap memengaruhi kapasitas nyata.

## Login Ubuntu dengan PPK

1. Jalankan `run_windows.bat`, pilih **PPK** atau **Otomatis**, lalu pilih file `.ppk`.
2. Isi username yang sesuai dengan pemilik key di VPS. Pada Ubuntu cloud sering `ubuntu`; pakai `root` hanya jika provider memang memasang key untuk akun root.
3. Isi **Key passphrase** hanya jika file PPK terenkripsi. Ini berbeda dari password akun Ubuntu maupun password sudo.
4. Biarkan password SSH kosong untuk membuktikan login benar-benar menggunakan key. Tekan **Tes Koneksi** dan pastikan log menyatakan autentikasi berhasil menggunakan PPK. Tes ini juga mengecek hak root/sudo.
5. Jika akun memakai sudo NOPASSWD, **Password sudo** boleh kosong. Jika sudo membutuhkan password, isi kolom tersebut dengan password akun Ubuntu.

Jika key ditolak server, public key pasangan PPK harus ada di `~/.ssh/authorized_keys` akun tersebut. Memperbaiki parser aplikasi tidak dapat memberi akses untuk key yang belum didaftarkan di server. Jangan kirim private key atau passphrase ke chat.

## Pengembangan di cloud/Linux

Checkout memakai sumber ZIP pengguna. GitHub `iskayanuhedei-byte/bot-wp` saat pemeriksaan awal belum memiliki commit. Paket versi 0.2.7 disediakan di folder `releases` repositori ini.

```bash
cd /workspace/bot-wp
python3 -m venv /workspace/.venvs/bot-wp
/workspace/.venvs/bot-wp/bin/python -m pip install -r requirements-runtime.txt
PYTHONPATH=src /workspace/.venvs/bot-wp/bin/python -m unittest discover -s tests -v
```

Tes interoperabilitas independen memerlukan PuTTYgen Linux **untuk pengujian saja**. Isi `BAGOESWP_TEST_PUTTYGEN` dengan lokasinya. GUI memakai Tkinter dan memerlukan display; lingkungan cloud ini menyediakan Xvfb. Build `.exe` harus dilakukan di Windows. Agent provisioning tetap ditargetkan ke Ubuntu 24.04; jangan menjalankan bootstrap pada host cloud Debian.

Lihat `HASIL-PEMERIKSAAN.md` untuk temuan, hasil tes, dan batas validasi.
