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
import oqs

BASE_URL = "http://127.0.0.1:8000/api"

def process_cvc(request):
    if request.method == "POST":
        print("Frontend: Entering process_cvc view.")
        cvc_code = request.POST.get("cvc")
        if not cvc_code:
            print("Frontend: CVC code is missing.")
            return JsonResponse({"error": "CVC code is required"}, status=400)

        print(f"Frontend: CVC code received: {cvc_code}")

        try:
            # Step 1: Initiate session with the main API
            print("Frontend: Initiating session with the main API...")
            session_response = requests.post(f"{BASE_URL}/session/initiate")
            session_data = session_response.json()
            session_id = session_data["sessionId"]
            server_public_key_pem = session_data["ecdhePublicKey"]
            kyber_public_key = base64.b64decode(session_data["kyberPublicKey"])
            print(f"Frontend: Session data received: {session_data}")

            # Step 2: Generate ECDHE keys
            print("Frontend: Generating ECDHE keys...")
            private_key, client_public_key_pem = generate_ecdhe_keys()
            print("Frontend: ECDHE keys generated successfully.")

            # Step 3: Perform hybrid key exchange
            print("Frontend: Performing hybrid key exchange...")
            ecdhe_shared_secret = derive_shared_secret(private_key, server_public_key_pem)
            print(f"Frontend: ECDHE shared secret derived: {ecdhe_shared_secret.hex()}")

            # Perform Kyber encryption
            print("Frontend: Performing Kyber encryption...")
            with oqs.KeyEncapsulation("Kyber512") as client_kem:
                kyber_ciphertext, kyber_shared_secret = client_kem.encap_secret(kyber_public_key)
            print(f"Frontend: Kyber encryption successful. Ciphertext: {kyber_ciphertext.hex()}, Shared Secret: {kyber_shared_secret.hex()}")

            # Combine ECDHE and Kyber shared secrets
            print("Frontend: Combining ECDHE and Kyber shared secrets...")
            shared_key = HKDF(
                algorithm=SHA256(),
                length=32,
                salt=None,
                info=b"hybrid-key",
            ).derive(ecdhe_shared_secret + kyber_shared_secret)
            print(f"Frontend: Combined hybrid shared key: {shared_key.hex()}")

            # Step 4: Encrypt the CVC code
            print("Frontend: Encrypting the CVC code...")
            encrypted_data, iv = encrypt_data(shared_key, cvc_code)
            print(f"Frontend: Encrypted CVC code: Ciphertext: {encrypted_data.hex()}, IV: {iv.hex()}")

            # Step 5: Upload encrypted data
            print("Frontend: Uploading encrypted data to the main API...")
            upload_payload = {
                "sessionId": session_id,
                "encryptedData": base64.b64encode(encrypted_data).decode(),
                "iv": base64.b64encode(iv).decode(),
                "ecdhePublicKey": client_public_key_pem.decode(),
                "kyberCiphertext": base64.b64encode(kyber_ciphertext).decode(),
            }
            upload_response = requests.post(f"{BASE_URL}/data/upload", json=upload_payload)
            print(f"Frontend: Upload response: {upload_response.status_code}, {upload_response.text}")

            if upload_response.status_code != 200:
                return JsonResponse({"error": "Error uploading encrypted data."}, status=500)

            # Step 6: Retrieve data list
            print("Frontend: Retrieving data list from the main API...")
            list_response = requests.get(f"{BASE_URL}/data/list/{session_id}")
            data_list = list_response.json()
            print(f"Frontend: Data list received: {data_list}")

            if not data_list:
                print("Frontend: No data found in the session.")
                return JsonResponse({"error": "No data found in session."}, status=404)

            # Step 7: Retrieve and decrypt the first data entry
            print("Frontend: Retrieving and decrypting the first data entry...")
            first_data_id = data_list[0]["id"]
            retrieve_payload = {
                "sessionId": session_id,
                "dataId": first_data_id,
                "ecdhePublicKey": client_public_key_pem.decode(),
                "kyberCiphertext": base64.b64encode(kyber_ciphertext).decode(),
            }
            retrieve_response = requests.post(f"{BASE_URL}/data/retrieve", json=retrieve_payload)
            if retrieve_response.status_code != 200:
                print(f"Frontend: Error during data retrieval: {retrieve_response.text}")
                return JsonResponse({"error": "Error retrieving data from the backend."}, status=500)

            retrieved_data = retrieve_response.json()
            print(f"Frontend: Retrieved data: {retrieved_data}")

            encrypted_data = base64.b64decode(retrieved_data["encryptedData"])
            iv = base64.b64decode(retrieved_data["iv"])
            plaintext = decrypt_data(shared_key, encrypted_data, iv)
            print(f"Frontend: Decrypted CVC code: {plaintext}")

            return JsonResponse({"success": True, "retrievedCVC": plaintext})

        except Exception as e:
            print(f"Frontend: Error occurred: {e}")
            return JsonResponse({"error": str(e)}, status=500)

    print("Frontend: Rendering index.html for GET request.")
    return render(request, "index.html")


# Helper Functions
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
    return shared_secret


def encrypt_data(key, plaintext):
    print("Frontend: Encrypting data with AES...")
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    print(f"Frontend: Applying PKCS7 padding... Padded plaintext length: {len(padded_data)}")
    return encrypted_data, iv


def decrypt_data(key, encrypted_data, iv):
    print(f"Frontend: Decrypting data with AES... Key: {key.hex()}, IV: {iv.hex()}")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode("utf-8")