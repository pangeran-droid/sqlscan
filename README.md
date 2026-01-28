# 🛡️ SQLScan

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**SQLScan** adalah alat pemindai kerentanan SQL Injection otomatis yang ringan dan cepat. Alat ini mendukung berbagai metode deteksi, mulai dari *error-based* hingga *blind time-based*, serta mampu memproses file request dari Burp Suite secara langsung.

---

## ✨ Fitur Utama

* **🎯 Target Fleksibel**: Scan satu URL, daftar URL dalam file, atau file HTTP request mentah.
* **🔍 Mode Deteksi Lengkap**:
    * **Error-Based**: Mendeteksi kesalahan sintaks database.
    * **Time-Based**: Menggunakan teknik *sleep* untuk konfirmasi celah.
    * **Union-Based**: (Aggressive) Mendeteksi melalui manipulasi query UNION.
    * **Potential Blind**: Analisis perbedaan panjang respon (Content-Length).
* **🧩 Header Scanning**: Injeksi pada header `User-Agent`, `Referer`, `Cookie`, dan lainnya.
* **⚡ Multi-threading**: Pemindaian cepat dengan 10 thread paralel.
* **📊 Output Terorganisir**: Hasil disimpan otomatis dalam format `.log` dan `.json`.

---

## ⚙️ Instalasi

1. Clone repository ini:
   ```bash
   git clone [https://github.com/username/sqlscan.git](https://github.com/username/sqlscan.git)
   cd sqlscan


Instal dependensi:
Bash

    pip install -r requirements.txt

🚀 Cara Penggunaan
Sintaks Dasar
Bash

python3 sqlscan.py [options] <target>

Opsi Argumen
Flag	Long Flag	Deskripsi
-h	--help	Menampilkan bantuan
-b	--burp	Scan file request mentah (Burp Suite format)
-t	--time	Aktifkan deteksi Time-based SQLi
-H	--scan-headers	Scan parameter di dalam HTTP Headers
-a	--aggressive	Aktifkan pengecekan agresif (UNION & Blind)
📄 Contoh Perintah

Scan URL tunggal dengan deteksi waktu:
Bash

python3 sqlscan.py "[http://example.com/search.php?id=1](http://example.com/search.php?id=1)" -t

Scan masal dari file targets.txt:
Bash

python3 sqlscan.py targets.txt -a

Scan dari file request Burp Suite (Full Scan):
Bash

python3 sqlscan.py -b request.txt -t -H -a

💾 Hasil Output (Results)

Setiap hasil pemindaian akan disimpan di folder results/:

    results/sqlscan.log: Log teks yang mencatat aktivitas pemindaian.

    results/sqlscan_results.json: Hasil temuan dalam format JSON untuk analisis data.

📂 Struktur Project
Plaintext

sqlscan/
├── sqlscan.py          # Script utama
├── requirements.txt    # Daftar dependensi
├── results/            # Folder output (otomatis dibuat)
│   ├── sqlscan.log
│   └── sqlscan_results.json
└── README.md           # Dokumentasi ini

⚠️ Disclaimer

Penggunaan SQLScan untuk menyerang target tanpa izin tertulis sebelumnya adalah ilegal. Penulis tidak bertanggung jawab atas kerusakan atau penyalahgunaan yang disebabkan oleh program ini. Gunakan hanya untuk tujuan edukasi dan pengujian keamanan yang legal.

MIT License © 2024 YourName