# Deteksi Serangan Menggunakan IDS Suricata

### Anggota Kelompok 9 
| No | Nama                                       | NRP         |
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

### Analisis Singkat

### Kesimpulan

