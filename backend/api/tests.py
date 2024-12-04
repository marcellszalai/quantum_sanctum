from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64

# Generate a random AES key and IV
key = get_random_bytes(16)  # 128-bit key for AES
iv = get_random_bytes(16)   # AES block size is 16 bytes

# Convert the plaintext to bytes
plaintext = '123'.encode()

# Pad the plaintext to make its length a multiple of AES block size (16 bytes)
padded_data = pad(plaintext, AES.block_size)

# Encrypt the data
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted_data = cipher.encrypt(padded_data)

# Base64 encode the encrypted data and IV for transport
encrypted_data_base64 = base64.b64encode(encrypted_data).decode('utf-8')
iv_base64 = base64.b64encode(iv).decode('utf-8')

# Print the result
print("Encrypted Data:", encrypted_data_base64)
print("IV:", iv_base64)