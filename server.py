import socket
import base64
import os
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

HOST = "192.168.63.46"
PORT = 65432

def des_encrypt(key, msg, mode, iv=None):
    des = DES.new(key, DES.MODE_CBC, iv) if mode == "CBC" else DES.new(key, DES.MODE_ECB)
    return base64.b64encode(des.encrypt(pad(msg.encode(), DES.block_size))).decode()

def des_decrypt(key, enc, mode, iv=None):
    des = DES.new(key, DES.MODE_CBC, iv) if mode == "CBC" else DES.new(key, DES.MODE_ECB)
    return unpad(des.decrypt(base64.b64decode(enc)), DES.block_size).decode()

def server():
    print("SERVER: Generating RSA key pair...")
    rsa_key = RSA.generate(2048)
    private_key = rsa_key
    public_key = rsa_key.publickey()

    print("SERVER: RSA key pair generated.\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"SERVER listening on {HOST}:{PORT}")

        conn, addr = s.accept()
        print(f"Client connected:", addr)

        # Kirim public key ke client
        conn.send(public_key.export_key())

        # Terima secret DES key terenkripsi
        encrypted_secret = conn.recv(4096)

        rsa_cipher = PKCS1_OAEP.new(private_key)
        secret_key = rsa_cipher.decrypt(encrypted_secret)

        print("SERVER: Secret key received:", secret_key)

        mode = conn.recv(1024).decode()
        print("MODE from client:", mode)

        while True:
            data = conn.recv(4096)
            if not data:
                break

            lines = dict(line.split("=", 1) for line in data.decode().split("\n") if "=" in line)

            iv = None if lines["IV"] == "-" else base64.b64decode(lines["IV"])

            decrypted = des_decrypt(secret_key, lines["DATA"], lines["MODE"], iv)
            print(f"Client says: {decrypted}")

            balas = input("Balas ke client: ")
            if balas.lower() == "exit":
                break

            iv_out = os.urandom(8) if mode == "CBC" else None
            encrypted_reply = des_encrypt(secret_key, balas, mode, iv_out)

            payload = "\n".join([
                f"MODE={mode}",
                f"IV={base64.b64encode(iv_out).decode() if iv_out else '-'}",
                f"DATA={encrypted_reply}",
                f"PLAIN={balas}"
            ])

            conn.send(payload.encode())

    print("SERVER closed.")

if __name__ == "__main__":
    server()
