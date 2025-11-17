import socket
import base64
import os
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

SERVER_ADDR = ("192.168.63.46", 65432)

def des_encrypt(key, msg, mode, iv=None):
    des = DES.new(key, DES.MODE_CBC, iv) if mode == "CBC" else DES.new(key, DES.MODE_ECB)
    return base64.b64encode(des.encrypt(pad(msg.encode(), DES.block_size))).decode()

def des_decrypt(key, enc, mode, iv=None):
    des = DES.new(key, DES.MODE_CBC, iv) if mode == "CBC" else DES.new(key, DES.MODE_ECB)
    return unpad(des.decrypt(base64.b64decode(enc)), DES.block_size).decode()

def client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(SERVER_ADDR)
        print("Tersambung ke server.")

        # Terima RSA public key dari server
        public_key_pem = s.recv(4096)
        public_key = RSA.import_key(public_key_pem)

        # Generate secret DES key (8 bytes)
        secret_key = os.urandom(8)
        print("Client secret key:", secret_key)

        # Enkripsi secret key pakai RSA server
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_secret = cipher_rsa.encrypt(secret_key)

        s.send(encrypted_secret)

        mode = input("Pilih mode (CBC/ECB): ").strip().upper()
        s.send(mode.encode())

        while True:
            msg = input("Kirim pesan: ")
            if msg.lower() == "exit":
                break

            iv_out = os.urandom(8) if mode == "CBC" else None
            cipher_text = des_encrypt(secret_key, msg, mode, iv_out)

            payload = "\n".join([
                f"MODE={mode}",
                f"IV={base64.b64encode(iv_out).decode() if iv_out else '-'}",
                f"DATA={cipher_text}",
                f"PLAIN={msg}"
            ])

            s.send(payload.encode())

            data = s.recv(4096)
            if not data:
                break

            lines = dict(line.split("=", 1) for line in data.decode().split("\n") if "=" in line)
            iv_in = None if lines["IV"] == "-" else base64.b64decode(lines["IV"])

            decrypted = des_decrypt(secret_key, lines["DATA"], lines["MODE"], iv_in)

            print("\nBalasan Server:")
            print("Teks asli     :", lines["PLAIN"])
            print("Terenkripsi   :", lines["DATA"])
            if mode == "CBC":
                print("IV            :", lines["IV"])
            print("Hasil decrypt :", decrypted)
            print()

if __name__ == "__main__":
    client()
