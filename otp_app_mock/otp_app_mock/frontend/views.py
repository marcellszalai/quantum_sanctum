# frontend/views.py

import requests
import base64
import json  # Import json module for formatting logs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.backends import default_backend
import os
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import oqs
from django.conf import settings
from django.template.defaulttags import register

# Register the get_item filter
@register.filter
def get_item(list, index):
    try:
        return list[index]
    except IndexError:
        return ''

BASE_URL = "http://127.0.0.1:8000/api"

def process_cvc(request):
    """
    Handles the processing of CVC codes, including encryption, uploading, and displaying logs.
    """
    # Initialize context variables
    session_info = {}
    cvc_data = []

    if request.method == "POST":
        print("Frontend: Entering process_cvc view.")
        cvc_code = request.POST.get("cvc")
        if not cvc_code:
            print("Frontend: CVC code is missing.")
            return JsonResponse({"error": "CVC code is required"}, status=400)

        print(f"Frontend: CVC code received: {cvc_code}")

        try:
            # Initialize or reuse session
            if 'session_id' in request.session:
                print("Frontend: Reusing existing session.")
                session_id = request.session['session_id']
                shared_key = base64.b64decode(request.session['shared_key'])
                client_public_key_pem = request.session['client_public_key_pem'].encode()
                kyber_ciphertext = base64.b64decode(request.session['kyber_ciphertext'])
                print(f"Frontend: Retrieved shared_key from session: {shared_key.hex()}")
                logs = [
                    "Reusing existing session.",
                    f"Session ID: {session_id}",
                    f"Shared Key (decoded): {shared_key.hex()}"
                ]
            else:
                # Step 1: Initiate session with the main API
                print("Frontend: Initiating session with the main API...")
                session_response = requests.post(f"{BASE_URL}/session/initiate")
                session_data = session_response.json()
                session_id = session_data["sessionId"]
                server_public_key_pem = session_data["ecdhePublicKey"]
                kyber_public_key = base64.b64decode(session_data["kyberPublicKey"])
                print(f"Frontend: Session data received: {session_data}")
                logs = [
                    "Initiating session with the main API.",
                    f"Session ID: {session_id}",
                    "Session data received:",
                    json.dumps(session_data, indent=4)  # Nicely formatted JSON
                ]

                # Step 2: Generate ECDHE keys
                print("Frontend: Generating ECDHE keys...")
                private_key, client_public_key_pem = generate_ecdhe_keys()
                print("Frontend: ECDHE keys generated successfully.")
                logs += [
                    "Generating ECDHE keys.",
                    "ECDHE keys generated successfully."
                ]

                # Step 3: Perform hybrid key exchange
                print("Frontend: Performing hybrid key exchange...")
                ecdhe_shared_secret = derive_shared_secret(private_key, server_public_key_pem)
                print(f"Frontend: ECDHE shared secret derived: {ecdhe_shared_secret.hex()}")
                logs += [
                    "Performing hybrid key exchange.",
                    f"ECDHE shared secret derived: {ecdhe_shared_secret.hex()}"
                ]

                # Perform Kyber encryption
                print("Frontend: Performing Kyber encryption...")
                with oqs.KeyEncapsulation("Kyber512") as client_kem:
                    kyber_ciphertext, kyber_shared_secret = client_kem.encap_secret(kyber_public_key)
                print(f"Frontend: Kyber encryption successful. Ciphertext: {kyber_ciphertext.hex()}, Shared Secret: {kyber_shared_secret.hex()}")
                logs += [
                    "Performing Kyber encryption.",
                    f"Kyber encryption successful. Ciphertext: {kyber_ciphertext.hex()}, Shared Secret: {kyber_shared_secret.hex()}"
                ]

                # Combine ECDHE and Kyber shared secrets
                print("Frontend: Combining ECDHE and Kyber shared secrets...")
                shared_key = HKDF(
                    algorithm=SHA256(),
                    length=32,
                    salt=None,
                    info=b"hybrid-key",
                ).derive(ecdhe_shared_secret + kyber_shared_secret)
                print(f"Frontend: Combined hybrid shared key: {shared_key.hex()}")
                logs += [
                    "Combining ECDHE and Kyber shared secrets.",
                    f"Combined hybrid shared key: {shared_key.hex()}"
                ]

                # Store session information in Django session
                request.session['session_id'] = session_id
                request.session['shared_key'] = base64.b64encode(shared_key).decode()
                request.session['client_public_key_pem'] = client_public_key_pem.decode()
                request.session['kyber_ciphertext'] = base64.b64encode(kyber_ciphertext).decode()
                print("Frontend: Session information stored in Django session.")
                logs.append("Session information stored in Django session.")

                # Assign session_info for template
                session_info = {
                    "session_id": session_id,
                    "shared_key": shared_key.hex(),
                    "client_public_key_pem": client_public_key_pem.decode(),
                    "kyber_ciphertext": kyber_ciphertext.hex(),
                }

            # Step 4: Encrypt the CVC code
            print("Frontend: Encrypting the CVC code...")
            encrypted_data, iv = encrypt_data(shared_key, cvc_code)
            print(f"Frontend: Encrypted CVC code: Ciphertext: {encrypted_data.hex()}, IV: {iv.hex()}")
            logs += [
                "Encrypting the CVC code.",
                f"Encrypted CVC code: Ciphertext: {encrypted_data.hex()}, IV: {iv.hex()}"
            ]

            # Step 5: Upload encrypted data
            print("Frontend: Uploading encrypted data to the main API...")
            upload_payload = {
                "sessionId": session_id,
                "encryptedData": base64.b64encode(encrypted_data).decode(),
                "iv": base64.b64encode(iv).decode(),
                "ecdhePublicKey": client_public_key_pem.decode(),
                "kyberCiphertext": request.session['kyber_ciphertext'],
            }
            upload_response = requests.post(f"{BASE_URL}/data/upload", json=upload_payload)
            print(f"Frontend: Upload response: {upload_response.status_code}, {upload_response.text}")
            logs += ["Uploading encrypted data to the main API."]
            if upload_response.status_code != 200:
                logs += [f"Error uploading encrypted data: {upload_response.text}"]
                # Store logs in session
                if 'logs' not in request.session:
                    request.session['logs'] = {}
                request.session['logs'][str(data_id)] = logs
                request.session.modified = True
                return JsonResponse({"error": "Error uploading encrypted data."}, status=500)
            else:
                logs.append("Encrypted data uploaded successfully.")

            # Get the id of the newly uploaded data
            # Since the backend returns only a message, we need to retrieve the latest data entry
            print("Frontend: Retrieving latest uploaded data...")
            list_response = requests.get(f"{BASE_URL}/data/list/{session_id}")
            data_list = list_response.json()
            if not data_list:
                logs.append("No data found in session after upload.")
                # Store logs in session
                if 'logs' not in request.session:
                    request.session['logs'] = {}
                request.session['logs'][str(data_id)] = logs
                request.session.modified = True
                return JsonResponse({"error": "No data found in session."}, status=404)
            latest_data = data_list[-1]
            data_id = latest_data["id"]
            logs.append(f"Uploaded Data ID: {data_id}")

            # Store logs in session, mapped to data_id
            if 'logs' not in request.session:
                request.session['logs'] = {}
            request.session['logs'][str(data_id)] = logs
            request.session.modified = True  # Mark the session as modified to save changes

            # Step 6: Retrieve data list and decrypt CVC codes
            print("Frontend: Retrieving data list from the main API...")
            cvc_list = []
            upload_times = []
            data_ids = []
            for data_entry in data_list:
                data_id_entry = data_entry["id"]
                retrieve_payload = {
                    "sessionId": session_id,
                    "dataId": data_id_entry,
                    "ecdhePublicKey": client_public_key_pem.decode(),
                    "kyberCiphertext": request.session['kyber_ciphertext'],
                }
                retrieve_response = requests.post(f"{BASE_URL}/data/retrieve", json=retrieve_payload)
                if retrieve_response.status_code != 200:
                    print(f"Frontend: Error retrieving data ID {data_id_entry}: {retrieve_response.text}")
                    continue

                retrieved_data = retrieve_response.json()
                print(f"Frontend: Retrieved data: {retrieved_data}")

                encrypted_data_retrieved = base64.b64decode(retrieved_data["encryptedData"])
                iv_retrieved = base64.b64decode(retrieved_data["iv"])
                plaintext = decrypt_data(shared_key, encrypted_data_retrieved, iv_retrieved)
                print(f"Frontend: Decrypted CVC code: {plaintext}")

                cvc_list.append(plaintext)
                upload_times.append(data_entry["uploaded_at"])
                data_ids.append(data_id_entry)

            # Assign CVC data for template with logs
            cvc_data = []
            for cvc, upload_time, data_id_entry in zip(cvc_list, upload_times, data_ids):
                logs_for_cvc = request.session.get('logs', {}).get(str(data_id_entry), [])
                cvc_data.append({
                    "cvc": cvc,
                    "upload_time": upload_time,
                    "data_id": data_id_entry,
                    "logs": logs_for_cvc
                })

            # Render the template with updated CVC list
            return render(request, "index.html", {
                "cvc_data": cvc_data,
                "session_info": session_info,
            })

        except Exception as e:
            print(f"Frontend: Error occurred: {e}")
            return JsonResponse({"error": str(e)}, status=500)

    # Handle GET request
    print("Frontend: Rendering index.html for GET request.")
    # On GET request, display existing CVCs if any
    if 'session_id' in request.session:
        try:
            session_id = request.session['session_id']
            list_response = requests.get(f"{BASE_URL}/data/list/{session_id}")
            data_list = list_response.json()
            cvc_list = []
            upload_times = []
            data_ids = []
            for data_entry in data_list:
                data_id_entry = data_entry["id"]
                retrieve_payload = {
                    "sessionId": session_id,
                    "dataId": data_id_entry,
                    "ecdhePublicKey": request.session['client_public_key_pem'],
                    "kyberCiphertext": request.session['kyber_ciphertext'],
                }
                retrieve_response = requests.post(f"{BASE_URL}/data/retrieve", json=retrieve_payload)
                if retrieve_response.status_code != 200:
                    continue

                retrieved_data = retrieve_response.json()
                encrypted_data_retrieved = base64.b64decode(retrieved_data["encryptedData"])
                iv_retrieved = base64.b64decode(retrieved_data["iv"])
                plaintext = decrypt_data(base64.b64decode(request.session['shared_key']), encrypted_data_retrieved, iv_retrieved)
                cvc_list.append(plaintext)
                upload_times.append(data_entry["uploaded_at"])
                data_ids.append(data_id_entry)

            # Assign CVC data for template with logs
            cvc_data = []
            for cvc, upload_time, data_id_entry in zip(cvc_list, upload_times, data_ids):
                logs = request.session.get('logs', {}).get(str(data_id_entry), [])
                cvc_data.append({
                    "cvc": cvc,
                    "upload_time": upload_time,
                    "data_id": data_id_entry,
                    "logs": logs
                })
        except Exception as e:
            print(f"Frontend: Error during GET request: {e}")

    return render(request, "index.html", {"cvc_data": cvc_data, "session_info": session_info})

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
    try:
        print(f"Frontend: Decrypting data with AES... Key: {key.hex()}, IV: {iv.hex()}")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        print(f"Frontend: Decrypted padded data length: {len(padded_data)}")
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        print(f"Frontend: Decrypted plaintext: {plaintext.decode('utf-8')}")
        return plaintext.decode("utf-8")
    except ValueError as e:
        print(f"Frontend: Decryption failed: {e}")
        raise ValueError("Invalid encryption data or padding.")