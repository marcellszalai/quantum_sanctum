import requests
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.backends import default_backend
import os
from django.shortcuts import render
from django.http import JsonResponse

BASE_URL = "http://127.0.0.1:8000/api"

def process_cvc(request):
    if request.method == "POST":
        cvc_code = request.POST.get("cvc")
        if not cvc_code:
            return JsonResponse({"error": "CVC code is required"}, status=400)

        try:
            # Step 1: Initiate session with the main Django API
            session_response = requests.post(f"{BASE_URL}/session/initiate")
            session_data = session_response.json()
            session_id = session_data["sessionId"]
            server_public_key_pem = session_data["ecdhePublicKey"]

            # Step 2: Generate ECDHE keys and derive a shared secret
            private_key, client_public_key_pem = generate_ecdhe_keys()
            shared_key = derive_shared_secret(private_key, server_public_key_pem)

            # Step 3: Encrypt the CVC code
            encrypted_data, iv = encrypt_data(shared_key, cvc_code)

            # Step 4: Upload encrypted CVC
            upload_payload = {
                "sessionId": session_id,
                "encryptedData": base64.b64encode(encrypted_data).decode(),
                "iv": base64.b64encode(iv).decode(),
            }
            requests.post(f"{BASE_URL}/data/upload", json=upload_payload)

            # Step 5: Retrieve data list
            list_response = requests.get(f"{BASE_URL}/data/list/{session_id}")
            data_list = list_response.json()

            # Step 6: Retrieve and decrypt the first entry
            first_data_id = data_list[0]["id"]
            retrieve_payload = {"sessionId": session_id, "dataId": first_data_id}
            retrieve_response = requests.post(f"{BASE_URL}/data/retrieve", json=retrieve_payload)
            retrieved_data = retrieve_response.json()
            encrypted_data = base64.b64decode(retrieved_data["encryptedData"])
            iv = base64.b64decode(retrieved_data["iv"])
            plaintext = decrypt_data(shared_key, encrypted_data, iv)

            # Render results
            return JsonResponse({"success": True, "retrievedCVC": plaintext})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return render(request, "index.html")


# Helper Functions (same as in your test.py)
def generate_ecdhe_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key_pem


def derive_shared_secret(private_key, server_public_key_pem):
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
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data, iv


def decrypt_data(key, encrypted_data, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode("utf-8")