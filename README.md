# 🛡️ Portofolio Cyber Security - Sabilillah Ramaniya Widodo

> **Empirical. Systematic. Ethical.**
> *Dokumentasi perjalanan pembelajaran teknis dan proyek keamanan siber.*

## 1. Pengantar Portofolio (Introduction)

### 👤 Tentang Saya
Halo! [cite_start]Saya **Sabilillah Ramaniya Widodo**, seorang *Cyber Security Enthusiast* yang berdedikasi untuk mempelajari dan menerapkan praktik terbaik dalam melindungi sistem dan data[cite: 3, 630]. [cite_start]Saat ini, saya sedang menyelesaikan program Bootcamp Cyber Security (Batch 4) dengan fokus pada *Vulnerability Assessment*, *Penetration Testing*, dan *Malware Analysis*[cite: 2, 629].

[cite_start]Portofolio ini berfungsi sebagai CV digital untuk mendemonstrasikan kemampuan teknis saya dalam mengamankan infrastruktur kritis serta analisis ancaman siber[cite: 526].

* **Peran:** Cyber Security Student / Practitioner
* [cite_start]**Minat Utama:** Penetration Testing, Threat Analysis, Vulnerability Management[cite: 531].
* [cite_start]**Sertifikasi & Pelatihan:** Bootcamp Cyber Security Batch 4 (Dibimbing.id)[cite: 2].

### 🛠️ Keahlian Teknis (Technical Skills)
Berdasarkan proyek yang telah diselesaikan, berikut adalah *stack* teknologi yang saya kuasai:

| Kategori | Tools & Konsep |
| :--- | :--- |
| **Network Analysis** | [cite_start]Wireshark, Nmap, TCP/IP Analysis[cite: 537]. |
| **Penetration Testing** | [cite_start]Metasploit Framework, Burp Suite, OpenVPN, SSH[cite: 12, 537]. |
| **Malware Analysis** | [cite_start]Any.Run (Dynamic), VirusTotal (Static), IDA Pro/Ghidra (Conceptual), MSFVenom[cite: 636, 785]. |
| **Sistem Operasi** | [cite_start]Linux (Debian/Kali), Windows[cite: 12, 653]. |
| **Frameworks** | [cite_start]MITRE ATT&CK, CVSS v4.0 Scoring, OWASP Top 10[cite: 251, 787]. |

---

## 📂 Project 1: Linux Server Vulnerability Assessment & Privilege Escalation

**Deskripsi:**
Proyek ini merupakan simulasi *Black Box Penetration Testing* pada mesin server berbasis Linux Debian. [cite_start]Tujuannya adalah mengidentifikasi celah keamanan yang memungkinkan eskalasi hak akses (*Privilege Escalation*) dari pengguna biasa menjadi *root*[cite: 12, 13].

### 2. Rekognisi & Scanning (Reconnaissance)
Tahap awal melibatkan pengumpulan informasi untuk memetakan permukaan serangan (*attack surface*).

* [cite_start]**Target:** 1 Mesin Debian (IP: `10.201.100.49`)[cite: 12, 42].
* **Metodologi:**
    * [cite_start]Akses awal dilakukan menggunakan protokol SSH melalui koneksi OpenVPN[cite: 12, 20].
    * [cite_start]Identifikasi identitas pengguna (`id`, `whoami`) dan pemeriksaan grup default[cite: 22, 23].
    * [cite_start]Enumerasi permission file sensitif dan konfigurasi `sudo`[cite: 25, 26].

### 3. Dokumentasi Eksploitasi (Exploitation)
*Peringatan: Seluruh eksploitasi dilakukan di lingkungan laboratorium terkontrol (TryHackMe) secara legal dan etis.*

Berikut adalah temuan kerentanan utama yang berhasil dieksploitasi:

#### 🚩 Temuan A: World-Readable /etc/shadow (Critical)
File `/etc/shadow` yang menyimpan *hash* password pengguna memiliki konfigurasi permission yang salah, sehingga dapat dibaca oleh semua pengguna (*world-readable*).

* **Bukti (Sanitized):**
    ```bash
    user@debian:~$ ls -l /etc/shadow
    -rw-r--rw- 1 root shadow 837 Aug 25 2019 /etc/shadow
    ```
    [cite_start]*[cite: 158, 168]*
* [cite_start]**Eksploitasi:** Hash password root berhasil di-*crack* menggunakan **John The Ripper** dengan wordlist `rockyou.txt`, menghasilkan password `password123`[cite: 30, 249].
* [cite_start]**CVSS Score:** 8.5 (High)[cite: 250].

#### 🚩 Temuan B: Misconfiguration Sudo NOPASSWD
Pengguna diizinkan menjalankan perintah tertentu sebagai *root* tanpa autentikasi password.

* **Bukti:**
    ```bash
    user@debian:~$ sudo -l
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    ...
    ```
    [cite_start]*[cite: 293-295]*
* **Eksploitasi:** Menggunakan binary `find` untuk melakukan *shell escape* dan mendapatkan akses root instan.
    ```bash
    user@debian:~$ sudo find . -exec /bin/sh \; -quit
    # whoami
    root
    ```
    [cite_start]*[cite: 314-316]*

#### 🚩 Temuan C: Vulnerable SUID Binary (Exim 4.84)
Ditemukan binary `exim` versi lawas (4.84) dengan bit SUID aktif yang rentan terhadap *Local Privilege Escalation* (CVE-2016-1531).

* [cite_start]**Eksploitasi:** Menjalankan script eksploitasi lokal `./cve-2016-1531.sh` yang memberikan akses root shell[cite: 360, 383].

### 4. Post-Exploitation & Konsep Privilege Escalation
Setelah mendapatkan akses *root*, dampak yang ditimbulkan meliputi:
* [cite_start]**Kontrol Penuh:** Penyerang memiliki kendali penuh atas sistem operasi[cite: 427].
* [cite_start]**Pencurian Data:** Akses ke seluruh file sistem, termasuk SSH Private Key root yang ditemukan terekspos (`/root/.ssh/root_key` readable)[cite: 431, 473].
* [cite_start]**Persistensi:** Penyerang dapat membuat *backdoor* atau akun baru untuk akses jangka panjang[cite: 504].

---

## 📂 Project 2: Malware Analysis Simulation (Trojan Backdoor)

**Deskripsi:**
Analisis perilaku *malicious software* menggunakan pendekatan *Sandboxing* (Analisis Dinamis) dan Statis. [cite_start]Malware sampel dibuat menggunakan `msfvenom` untuk mensimulasikan serangan *Reverse Shell*[cite: 636].

### 2. Rekognisi & Pembuatan Sampel
* **Nama File:** `dibimbing.exe`
* [cite_start]**Payload:** `windows/meterpreter/reverse_https` (Komunikasi terenkripsi via HTTPS)[cite: 656].
* **Teknik:** *Reverse Engineering* perilaku malware yang menghubungi server penyerang (C2).

### 3. Dokumentasi Eksploitasi & Analisis (Lab Environment)

#### Analisis Statis (VirusTotal)
* [cite_start]**Identitas File (Hash SHA-256):** `ba5d63bcd091ba55e1fe25de5752561a18d0aa3a...`[cite: 814, 888].
* [cite_start]**Deteksi:** 51 dari 71 vendor keamanan mendeteksi file ini sebagai berbahaya (*Malicious*)[cite: 812].

#### Analisis Dinamis (Any.Run Sandbox)
Berdasarkan eksekusi di lingkungan aman, malware menunjukkan *Indicator of Compromise* (IOC) berikut:
* [cite_start]**Network Activity:** Terdeteksi koneksi TCP persisten ke IP penyerang (`192.168.20.128`) pada port `8080`[cite: 886].
* [cite_start]**Registry Modification (MITRE ATT&CK T1012):** Malware membaca pengaturan keamanan Internet Explorer dan proxy untuk memastikan koneksi keluar tidak diblokir[cite: 788, 801].

### 4. Post-Exploitation (Konseptual)
Jika malware ini berhasil dieksekusi di komputer korban:
* [cite_start]**Remote Access:** Penyerang mendapatkan sesi *Meterpreter*, memungkinkan eksekusi perintah jarak jauh, *keylogging*, dan pengambilan tangkapan layar[cite: 735].
* [cite_start]**Stealth:** Proses berjalan di latar belakang tanpa antarmuka pengguna, sulit dideteksi oleh pengguna awam[cite: 771].

---

## 5. Laporan Akhir & Finalisasi (Final Report & Mitigation)

Sebagai penutup portofolio, berikut adalah rangkuman rekomendasi mitigasi strategis berdasarkan kedua proyek di atas untuk meningkatkan postur keamanan organisasi.

### 🛡️ Strategi Mitigasi (Defense in Depth)

**Untuk Server Linux (VAPT Findings):**
1.  [cite_start]**Hardening Permission:** Pastikan permission file `/etc/shadow` diatur ke `640` dan kunci SSH (`.ssh/`) diatur ke `600`[cite: 282, 506].
2.  [cite_start]**Prinsip Least Privilege:** Hapus konfigurasi `NOPASSWD` di file `sudoers` untuk binary yang memungkinkan akses shell (seperti `find`, `nano`, `vim`)[cite: 358].
3.  [cite_start]**Patch Management:** Selalu perbarui paket perangkat lunak (seperti Exim) ke versi terbaru untuk menambal CVE yang diketahui[cite: 429].

**Untuk Pencegahan Malware:**
1.  [cite_start]**Endpoint Detection & Response (EDR):** Implementasikan solusi EDR untuk mendeteksi perilaku anomali seperti koneksi *reverse shell* secara *real-time*[cite: 936].
2.  [cite_start]**Application Whitelisting:** Batasi eksekusi file `.exe` hanya dari sumber yang terdaftar dan terverifikasi[cite: 937].
3.  [cite_start]**User Awareness:** Pelatihan rutin kepada pengguna untuk tidak mengunduh atau menjalankan file dari sumber yang tidak dikenal, karena malware sering didistribusikan melalui rekayasa sosial[cite: 941].

***

*Disclaimer: Portofolio ini disusun untuk tujuan pendidikan dan demonstrasi keahlian profesional. Seluruh aktivitas pengujian dilakukan di lingkungan laboratorium yang diizinkan.*
