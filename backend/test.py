import requests
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# Server URL (update if necessary)
BASE_URL = "http://127.0.0.1:8000/api"

# Function to encrypt data with AES CBC using the symmetric key
def encrypt_with_aes256(aes_key, plaintext):
    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(iv).decode('utf-8')

# Function to initiate a session (gets session ID and symmetric key)
def initiate_session():
    response = requests.post(f"{BASE_URL}/session/initiate")
    if response.status_code == 200:
        session_data = response.json()
        print("Session initiated successfully:", session_data)
        return session_data['session_id'], base64.b64decode(session_data['shared_symmetric_key'])
    else:
        print("Error initiating session:", response.json())
        return None, None

# Function to upload encrypted data
def upload_data(session_id, encrypted_data, iv):
    data = {
        'sessionId': session_id,
        'encryptedData': encrypted_data,
        'iv': iv
    }
    response = requests.post(f"{BASE_URL}/data/upload", json=data)
    if response.status_code == 200:
        print("Data uploaded successfully:", response.json())
    else:
        print("Error uploading data:", response.json())

def main():
    # Step 1: Initiate session and get symmetric key
    session_id, symmetric_key = initiate_session()
    if session_id is None:
        return

    # Step 2: Encrypt data to upload (data = '123') using the session's symmetric key
    encrypted_data, iv = encrypt_with_aes256(symmetric_key, "123")
    
    # Step 3: Upload encrypted data
    upload_data(session_id, encrypted_data, iv)

if __name__ == "__main__":
    main()