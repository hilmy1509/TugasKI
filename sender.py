import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import os
import getpass  

HOST = '127.0.0.1'  
PORT = 65433       

key = b'1234567890123456'  

def encrypt_message(message):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

print("Masukkan pesan yang ingin dienkripsi dan dikirim:")

user_input = ""
while True:
    char = getpass.getpass(prompt="")  
    if char == '':  
        break
    user_input += char  

    encrypted_partial_message = encrypt_message(user_input)
    print("Pesan terenkripsi sementara:", encrypted_partial_message)

encrypted_message = encrypt_message(user_input)
print("Pesan terenkripsi yang akan dikirim:", encrypted_message)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(encrypted_message.encode('utf-8'))
    print("Pesan terenkripsi telah dikirim")
