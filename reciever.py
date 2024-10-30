import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64


HOST = '127.0.0.1'  
PORT = 65433        

key = b'1234567890123456'  

def decrypt_message(encrypted_message):
    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
    return decrypted_data.decode('utf-8')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("Server menunggu koneksi...")
    conn, addr = s.accept()
    with conn:
        print('Terhubung oleh', addr)
        
        encrypted_message = conn.recv(1024).decode('utf-8')
        print("Pesan terenkripsi diterima:", encrypted_message)
        
        try:
            decrypted_message = decrypt_message(encrypted_message)
            print("Pesan setelah didekripsi:", decrypted_message)
        except Exception as e:
            print("Gagal mendekripsi pesan:", e)
