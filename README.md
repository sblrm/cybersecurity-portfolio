# Portofolio Cyber Security - Sabilillah Ramaniya Widodo

> **Empirical. Systematic. Ethical.**

### About Me
Halo! Saya **Sabilillah Ramaniya Widodo**, seorang DevOps dan CyberSec Enthusiast yang berdedikasi untuk mempelajari dan menerapkan praktik terbaik dalam melindungi sistem dan data. Saat ini, saya sedang menjalani pendidikan Sarjana jurusan Computer Science di Binus University dan sedang menyelesaikan program Bootcamp Cyber Security di Dibimbing.id dengan fokus pada *Offensive Security*.

Portofolio ini berfungsi sebagai CV digital untuk mendemonstrasikan kemampuan teknis saya dalam mengamankan infrastruktur kritis serta analisis ancaman siber.

* **Peran:** Programmer / Pentester
* **Minat Utama:** DevSecOps, penetration testing, threat analysis, vulnerability management.
* **Sertifikasi & Pelatihan:** Bootcamp Cyber Security (Dibimbing.id).

### Keahlian teknis (Technical skills)
Berikut adalah *stack* teknologi apa saja yang saya gunakan:

| Kategori | Tools & konsep |
| :--- | :--- |
| **Network analysis** | Wireshark, Nmap, TCP/IP Analysis. |
| **Penetration testing** | Metasploit Framework, Burp Suite, OpenVPN, SSH. |
| **Malware analysis** | Any.Run (Dynamic), VirusTotal (Static), IDA Pro/Ghidra (Conceptual), MSFVenom. |
| **Sistem operasi** | Linux (Kali Linux), Windows. |
| **Frameworks** | MITRE ATT&CK, CVSS v4.0 Scoring, OWASP Top 10. |

---

This repository serves as a showcase of my technical capabilities in Cyber Security. Below are selected highlights from my laboratory assessments and projects, focusing on Vulnerability Assessment, Penetration Testing, and Malware Analysis. 
## Project 1: Linux server vulnerability assessment & privilege escalation

**Deskripsi:**
Proyek ini merupakan simulasi *Black Box Penetration Testing* pada mesin server berbasis Linux Debian. Tujuannya adalah mengidentifikasi celah keamanan yang memungkinkan eskalasi hak akses (*Privilege Escalation*) dari pengguna biasa menjadi *root*.

### 2. Rekognisi & scanning (Reconnaissance)
Tahap awal melibatkan pengumpulan informasi untuk memetakan permukaan serangan (*attack surface*).

* **Target:** 1 Mesin Debian (IP: `10.201.100.49`).
* **Metodologi:**
    * Akses awal dilakukan menggunakan protokol SSH melalui koneksi OpenVPN.
    * Identifikasi identitas pengguna (`id`, `whoami`) dan pemeriksaan grup default.
    * Enumerasi permission file sensitif dan konfigurasi `sudo`.

### 3. Dokumentasi eksploitasi (Exploitation)

Berikut adalah temuan kerentanan utama yang berhasil dieksploitasi:

#### Temuan A: World-Readable /etc/shadow (Critical)
File `/etc/shadow` yang menyimpan *hash* password pengguna memiliki konfigurasi permission yang salah, sehingga dapat dibaca oleh semua pengguna (*world-readable*).

* **Bukti (Sanitized):**
    ```bash
    user@debian:~$ ls -l /etc/shadow
    -rw-r--rw- 1 root shadow 837 Aug 25 2019 /etc/shadow
    ```
* **Eksploitasi:** Hash password root berhasil di-*crack* menggunakan **John The Ripper** dengan wordlist `rockyou.txt`, menghasilkan password `password123`.
* **CVSS Score:** 8.5 (High).

#### Temuan B: Misconfiguration Sudo NOPASSWD
Pengguna diizinkan menjalankan perintah tertentu sebagai *root* tanpa autentikasi password.

* **Bukti:**
    ```bash
    user@debian:~$ sudo -l
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    ...
    ```
* **Eksploitasi:** Menggunakan binary `find` untuk melakukan *shell escape* dan mendapatkan akses root instan.
    ```bash
    user@debian:~$ sudo find . -exec /bin/sh \; -quit
    # whoami
    root
    ```

#### Temuan C: Vulnerable SUID Binary (Exim 4.84)
Ditemukan binary `exim` versi lawas (4.84) dengan bit SUID aktif yang rentan terhadap *Local Privilege Escalation* (CVE-2016-1531).

* **Eksploitasi:** Menjalankan script eksploitasi lokal `./cve-2016-1531.sh` yang memberikan akses root shell.

### 4. Post-Exploitation & konsep privilege escalation
Setelah mendapatkan akses *root*, dampak yang ditimbulkan meliputi:
* **Kontrol penuh:** Penyerang memiliki kendali penuh atas sistem operasi.
* **Pencurian data:** Akses ke seluruh file sistem, termasuk SSH Private Key root yang ditemukan terekspos (`/root/.ssh/root_key` readable).
* **Persistensi:** Penyerang dapat membuat *backdoor* atau akun baru untuk akses jangka panjang.

---

## Project 2: Malware analysis simulation (Trojan backdoor)

**Deskripsi:**
Analisis perilaku *malicious software* menggunakan pendekatan *Sandboxing* (Analisis Dinamis) dan Statis. Malware sampel dibuat menggunakan `msfvenom` untuk mensimulasikan serangan *Reverse Shell*.

### 2. Rekognisi & Pembuatan Sampel
* **Nama File:** `dibimbing.exe`
* **Payload:** `windows/meterpreter/reverse_https` (Komunikasi terenkripsi via HTTPS).
* **Teknik:** *Reverse Engineering* perilaku malware yang menghubungi server penyerang (C2).

### 3. Dokumentasi eksploitasi & analisis (Lab environment)

#### Analisis statis (VirusTotal)
* **Identitas File (Hash SHA-256):** `ba5d63bcd091ba55e1fe25de5752561a18d0aa3a...`.
* **Deteksi:** 51 dari 71 vendor keamanan mendeteksi file ini sebagai berbahaya (*Malicious*).

#### Analisis dinamis (Any.Run Sandbox)
Berdasarkan eksekusi di lingkungan aman, malware menunjukkan *Indicator of Compromise* (IOC) berikut:
* **Network activity:** Terdeteksi koneksi TCP persisten ke IP penyerang (`192.168.20.128`) pada port `8080`.
* **Registry modification (MITRE ATT&CK T1012):** Malware membaca pengaturan keamanan Internet Explorer dan proxy untuk memastikan koneksi keluar tidak diblokir.

### 4. Post-Exploitation (Konseptual)
Jika malware ini berhasil dieksekusi di komputer korban:
* **Remote access:** Penyerang mendapatkan sesi *meterpreter*, memungkinkan eksekusi perintah jarak jauh, *keylogging*, dan pengambilan tangkapan layar.
* **Stealth:** Proses berjalan di latar belakang tanpa antarmuka pengguna, sulit dideteksi oleh pengguna awam.

---

## 5. Laporan akhir & Finalisasi (Final report & mitigation)

Berikut adalah rangkuman rekomendasi mitigasi strategis berdasarkan kedua proyek di atas untuk meningkatkan postur keamanan organisasi.

### Strategi mitigasi (Defense in Depth)

**Untuk server linux (VAPT findings):**
1.  **Hardening permission:** Pastikan permission file `/etc/shadow` diatur ke `640` dan kunci SSH (`.ssh/`) diatur ke `600`.
2.  **Prinsip least privilege:** Hapus konfigurasi `NOPASSWD` di file `sudoers` untuk binary yang memungkinkan akses shell (seperti `find`, `nano`, `vim`).
3.  **Patch management:** Selalu perbarui paket perangkat lunak (seperti Exim) ke versi terbaru untuk menambal CVE yang diketahui.

**Untuk Pencegahan Malware:**
1.  **Endpoint detection & Response (EDR):** Implementasikan solusi EDR untuk mendeteksi perilaku anomali seperti koneksi *reverse shell* secara *real-time*.
2.  **Application whitelisting:** Batasi eksekusi file `.exe` hanya dari sumber yang terdaftar dan terverifikasi.
3.  **User awareness:** Pelatihan rutin kepada pengguna untuk tidak mengunduh atau menjalankan file dari sumber yang tidak dikenal, karena malware sering didistribusikan melalui rekayasa sosial.
