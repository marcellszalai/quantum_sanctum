import requests
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.backends import default_backend
import os

# Server base URL
BASE_URL = "http://127.0.0.1:8000/api"
CVC_CODE = "747"  # The data to be stored securely


def generate_ecdhe_keys():
    """Generates ECDHE key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key_pem


def derive_shared_secret(private_key, server_public_key_pem):
    """Derives a shared secret using ECDHE."""
    server_public_key = serialization.load_pem_public_key(
        server_public_key_pem.encode(), backend=default_backend()
    )
    shared_secret = private_key.exchange(ec.ECDH(), server_public_key)
    derived_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"session-key",
    ).derive(shared_secret)
    return derived_key


def encrypt_data(key, plaintext):
    """Encrypts plaintext using AES."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data, iv


def decrypt_data(key, encrypted_data, iv):
    """Decrypts data using AES."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode('utf-8')


def session_initiate():
    """Initiates a session with the server."""
    url = f"{BASE_URL}/session/initiate"
    response = requests.post(url)
    if response.status_code == 200:
        data = response.json()
        print(f"Session initiated: {data}")
        return data["sessionId"], data["ecdhePublicKey"]
    else:
        print(f"Failed to initiate session: {response.text}")
        return None, None


def upload_data(session_id, public_key_pem, encrypted_data, iv):
    """Uploads encrypted data to the server."""
    url = f"{BASE_URL}/data/upload"
    payload = {
        "sessionId": session_id,
        "encryptedData": base64.b64encode(encrypted_data).decode(),
        "iv": base64.b64encode(iv).decode(),
    }
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        print("Data uploaded successfully.")
    else:
        print(f"Failed to upload data: {response.text}")


def list_uploaded_data(session_id):
    """Fetches a list of all data uploaded for a session."""
    url = f"{BASE_URL}/data/list/{session_id}"
    response = requests.get(url)
    if response.status_code == 200:
        data_list = response.json()
        print(f"Uploaded data entries: {data_list}")
        return data_list
    else:
        print(f"Failed to list uploaded data: {response.text}")
        return None


def retrieve_data(session_id, data_id, private_key, server_public_key_pem):
    """Fetches a specific data entry and decrypts it."""
    # Derive shared secret with the server's public key
    shared_key = derive_shared_secret(private_key, server_public_key_pem)

    # Send a request to retrieve the encrypted data
    url = f"{BASE_URL}/data/retrieve"
    payload = {
        "sessionId": session_id,
        "dataId": data_id,
    }
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        encrypted_data = base64.b64decode(data["encryptedData"])
        iv = base64.b64decode(data["iv"])

        # Decrypt the data using the shared key
        plaintext = decrypt_data(shared_key, encrypted_data, iv)
        print(f"Retrieved plaintext: {plaintext}")
        return plaintext
    else:
        print(f"Failed to retrieve data: {response.text}")
        return None


if __name__ == "__main__":
    # Step 1: Initiate session with the server
    session_id, server_public_key_pem = session_initiate()
    if not session_id or not server_public_key_pem:
        exit()

    # Step 2: Generate ECDHE keys and derive shared secret
    private_key, client_public_key_pem = generate_ecdhe_keys()
    shared_key = derive_shared_secret(private_key, server_public_key_pem)

    # Step 3: Encrypt and upload data
    data_to_upload = "747"  # Simulated data
    encrypted_data, iv = encrypt_data(shared_key, data_to_upload)
    upload_data(session_id, client_public_key_pem, encrypted_data, iv)

    # Step 4: Retrieve data list
    data_list = list_uploaded_data(session_id)

    # Step 5: Retrieve a specific data entry
    if data_list:
        first_data_id = data_list[0]["id"]
        retrieve_data(session_id, first_data_id, private_key, server_public_key_pem)