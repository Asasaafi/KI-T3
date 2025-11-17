# KI-T3

|     NRP     | Nama                          |
|:-----------:|:------------------------------:|
| 5025231202  | Lailatul Annisa Fitriana       |

Program ini mengimplementasikan komunikasi dua device (client dan server) yang saling mengirim dan menerima pesan secara aman menggunakan kombinasi **RSA** dan **DES**:

1. **RSA** digunakan untuk *public key distribution of secret keys*  
   - Client *tidak mengetahui* secret key server  
   - Server *tidak mengetahui* secret key client  
   - Server mengirim **public key RSA** kepada client  
   - Client membuat secret key DES (8 byte), lalu mengenkripsinya menggunakan RSA  
   - Server mendekripsi secret key tersebut menggunakan private key RSA  
   → Setelah itu kedua pihak memiliki secret key yang sama

2. **DES (CBC/ECB)** digunakan untuk enkripsi isi pesan  
   - Mode CBC menggunakan IV  
   - Mode ECB tanpa IV  
   - Client dan server dapat mengirim pesan secara **vice-versa** (bergantian)

## Struktur File

- **client.py** → program sisi client  
- **server.py** → program sisi server

## Cara Menjalankan

### 1. Install library yang diperlukan
```bash
pip install pycryptodome
