# Panduan Deploy AI Guru (GitHub + Netlify)

## Struktur repo
```
public/index.html        halaman login (publik)
public/admin.html        panel admin (publik, dilindungi password admin)
protected/app.html       aplikasi utama (TIDAK publik, hanya lewat login)
netlify/functions/*.mjs  backend: login, logout, log, admin, app
netlify/lib/core.mjs     kode bersama
netlify.toml, package.json, .gitignore
```
Untuk memperbarui aplikasi, cukup ganti `protected/app.html` lalu commit.

## 1. Upload ke GitHub
Cara web: buat repository baru (Private disarankan), klik Add file > Upload files, seret SEMUA isi folder
(termasuk folder public, protected, netlify beserta file di dalamnya), lalu Commit changes.
Cara git:
```
git init && git add . && git commit -m "AI Guru"
git branch -M main
git remote add origin https://github.com/USERNAME/NAMA-REPO.git
git push -u origin main
```
Jika repo lama berisi folder netlify/functions atau netlify.toml lama, hapus dulu agar tidak bentrok.

## 2. Hubungkan ke Netlify
Netlify > Add new site > Import an existing project > GitHub > pilih repo.
Build command: kosongkan. Publish directory: terisi otomatis `public` dari netlify.toml. Klik Deploy.

## 3. Environment variables (Site configuration > Environment variables > Add a variable)
| Nama | Wajib | Isi |
|---|---|---|
| ADMIN_PASSWORD | Ya | Password panel admin. Pilih yang panjang dan sulit ditebak. Centang "Contains secret values". |
| SESSION_SECRET | Ya | Kunci rahasia untuk menandatangani cookie login. Minimal 32 karakter acak. Centang "Contains secret values". Jika diganti, semua guru harus login ulang. |

Contoh membuat SESSION_SECRET: di Terminal jalankan `openssl rand -hex 32`, atau pakai pembuat password acak (64 karakter huruf/angka).
Biarkan Scopes dan Deploy contexts pada pilihan default (semua). Setelah menyimpan variabel,
buka Deploys > Trigger deploy > Clear cache and deploy site. Variabel baru hanya terbaca setelah deploy ulang.
Penyimpanan token/sesi/log memakai Netlify Blobs yang aktif otomatis, tanpa pengaturan tambahan.
API key Gemini/Claude/ChatGPT TIDAK disimpan di Netlify; tiap guru mengisinya sendiri di menu Pengaturan AI.

## 4. Cara memakai
1. Buka https://NAMA-SITUS.netlify.app/admin.html, masuk dengan ADMIN_PASSWORD.
2. Buat token (isi nama, jumlah, masa berlaku dalam hari; dihitung sejak token pertama dipakai).
3. Bagikan token (format GURU-XXXX-XXXX-XXXX-XXXX) ke guru.
4. Guru membuka alamat situs, memasukkan token, lalu masuk ke /app.
5. Di panel admin: perpanjang, cabut, hapus token, lihat sesi online, akhiri sesi, dan lihat log.
Tampilan /app yang benar menampilkan tulisan "versi v9b" di halaman Pengaturan AI dan 3 pilihan penyedia AI.

## Jika ada masalah
- Admin muncul "ADMIN_PASSWORD belum diatur" atau login guru muncul "SESSION_SECRET belum diatur": variabelnya belum ada, kurang dari 32 karakter, atau belum deploy ulang.
- /app kembali ke halaman login terus: token dicabut/kedaluwarsa, atau cookie diblokir browser.
- Halaman lama masih tampil: cek Deploys berstatus Published, lalu hapus data situs di browser.
- Function error "protected/app.html tidak ditemukan": pastikan folder protected ada di repo dan netlify.toml
  memuat included_files = ["protected/**"].
- Deploy log gagal saat install: pastikan package.json ada di root repo.
