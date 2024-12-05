from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import oqs
import os
import base64
from .models import Session, UploadedData
from .serializers import UploadedDataSerializer

from cryptography.hazmat.primitives import serialization

def load_private_key(pem_key):
    """Deserialize a PEM-encoded private key."""
    return serialization.load_pem_private_key(pem_key, password=None, backend=default_backend())


# Helper Functions
def hybrid_key_exchange(ecdhe_private_key, ecdhe_public_key_client, kyber_private_key, kyber_ciphertext):
    """Perform a hybrid key exchange combining ECDHE and Kyber."""
    print("Backend: Calculating ECDHE shared secret...")
    ecdhe_shared_secret = ecdhe_private_key.exchange(ec.ECDH(), ecdhe_public_key_client)
    print(f"Backend: ECDHE shared secret calculated: {ecdhe_shared_secret.hex()}")

    print("Backend: Decapsulating Kyber ciphertext to obtain shared secret...")
    with oqs.KeyEncapsulation("Kyber512", secret_key=kyber_private_key) as server_kem:
        kyber_shared_secret = server_kem.decap_secret(kyber_ciphertext)
    print(f"Backend: Kyber shared secret obtained: {kyber_shared_secret.hex()}")

    print("Backend: Combining ECDHE and Kyber shared secrets...")
    combined_secret = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"hybrid-key",
    ).derive(ecdhe_shared_secret + kyber_shared_secret)
    print(f"Backend: Combined hybrid secret derived: {combined_secret.hex()}")

    return combined_secret


def aes_encrypt(key, plaintext_bytes):
    print(f"Backend: Encrypting data with AES... Key: {key.hex()}")
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    print("Backend: Applying PKCS7 padding...")
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_bytes) + padder.finalize()

    print(f"Backend: Padded plaintext length: {len(padded_data)}")
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    print(f"Backend: Ciphertext: {ciphertext.hex()}, IV: {iv.hex()}")

    return ciphertext, iv


def aes_decrypt(key, ciphertext, iv):
    try:
        print(f"Backend: Decrypting data with AES... Key: {key.hex()}, IV: {iv.hex()}")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        print(f"Backend: Decrypted padded data length: {len(padded_data)}")

        print("Backend: Removing PKCS7 padding...")
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        print(f"Backend: Decrypted plaintext: {plaintext.decode('utf-8')}")

        return plaintext
    except ValueError as e:
        print(f"Backend: Decryption failed: {e}")
        raise ValueError("Invalid encryption data or padding.")



@api_view(['POST'])
def session_initiate(request):
    """Initiates a session and provides ECDHE and Kyber public keys."""
    session_id = os.urandom(16).hex()

    # Generate ECDHE keys
    ecdhe_private_key = ec.generate_private_key(ec.SECP256R1())
    ecdhe_public_key = ecdhe_private_key.public_key()

    # Generate Kyber keys
    with oqs.KeyEncapsulation("Kyber512") as server_kem:
        kyber_public_key = server_kem.generate_keypair()
        kyber_private_key = server_kem.export_secret_key()

    # Store session details
    session = Session.objects.create(
        session_id=session_id,
        ecdhe_private_key=ecdhe_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        ecdhe_public_key=ecdhe_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        kyber_public_key=kyber_public_key,
        kyber_private_key=kyber_private_key,
    )
    session.set_expiration(minutes=5)

    response_data = {
        "sessionId": session_id,
        "ecdhePublicKey": session.ecdhe_public_key.decode(),
        "kyberPublicKey": base64.b64encode(kyber_public_key).decode(),
    }
    return Response(response_data, status=status.HTTP_200_OK)


@api_view(['POST'])
def data_upload(request):
    """Handles hybrid encryption and saves data."""
    session_id = request.data.get("sessionId")
    ecdhe_client_public_key_pem = request.data.get("ecdhePublicKey")
    kyber_ciphertext = base64.b64decode(request.data.get("kyberCiphertext"))
    encrypted_data = base64.b64decode(request.data.get("encryptedData"))
    iv = base64.b64decode(request.data.get("iv"))

    try:
        print(f"Backend: Retrieving session for ID: {session_id}")
        session = Session.objects.get(session_id=session_id, is_valid=True)
    except Session.DoesNotExist:
        print("Backend: Session does not exist or is invalid.")
        return Response({"error": "Invalid session"}, status=status.HTTP_400_BAD_REQUEST)

    if session.has_expired():
        print("Backend: Session has expired.")
        return Response({"error": "Session has expired"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Load the server's ECDHE private key
        print("Backend: Loading ECDHE private key...")
        ecdhe_private_key = load_private_key(session.ecdhe_private_key)

        # Load client ECDHE public key
        print("Backend: Loading client's ECDHE public key...")
        ecdhe_client_public_key = serialization.load_pem_public_key(
            ecdhe_client_public_key_pem.encode(), backend=default_backend()
        )

        # Perform hybrid key exchange
        print("Backend: Performing hybrid key exchange...")
        shared_key = hybrid_key_exchange(
            ecdhe_private_key,
            ecdhe_client_public_key,
            session.kyber_private_key,
            kyber_ciphertext,
        )
        print(f"Backend: Shared key for decryption: {shared_key.hex()}")

        # Decrypt client-encrypted data
        print("Backend: Decrypting the received data...")
        decrypted_data = aes_decrypt(shared_key, encrypted_data, iv)
        print(f"Backend: Decrypted CVC data: {decrypted_data.decode()}")

        # Re-encrypt the data using Kyber
        print("Backend: Re-encrypting data with Kyber...")
        kyber_encrypted_data, kyber_iv = aes_encrypt(shared_key, decrypted_data)

        # Save the encrypted data
        print("Backend: Saving encrypted data to the database...")
        UploadedData.objects.create(session=session, encrypted_data=kyber_encrypted_data, iv=kyber_iv)

        return Response({"message": "Data uploaded and re-encrypted."}, status=status.HTTP_200_OK)

    except Exception as e:
        print(f"Backend: Error during data upload: {e}")
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def retrieve_data(request):
    """Decrypts Kyber layer and returns client-encrypted data."""
    print("Backend: Entering retrieve_data endpoint...")
    session_id = request.data.get("sessionId")
    data_id = request.data.get("dataId")
    ecdhe_public_key_pem = request.data.get("ecdhePublicKey")

    if not all([session_id, data_id, ecdhe_public_key_pem]):
        print("Backend: Missing session ID, data ID, or ECDHE public key.")
        return Response({"error": "Missing required data (sessionId, dataId, or ecdhePublicKey)."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        print(f"Backend: Retrieving session for ID: {session_id}")
        session = Session.objects.get(session_id=session_id, is_valid=True)
    except Session.DoesNotExist:
        print("Backend: Session not found or invalid.")
        return Response({"error": "Invalid session"}, status=status.HTTP_400_BAD_REQUEST)

    if session.has_expired():
        print("Backend: Session has expired.")
        return Response({"error": "Session has expired"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        print(f"Backend: Retrieving data entry for ID: {data_id}")
        data_entry = UploadedData.objects.get(id=data_id, session=session)
    except UploadedData.DoesNotExist:
        print("Backend: Data entry not found.")
        return Response({"error": "No data found for this ID in this session"}, status=status.HTTP_404_NOT_FOUND)

    # Load ECDHE private key
    print("Backend: Loading ECDHE private key...")
    ecdhe_private_key = serialization.load_pem_private_key(
        session.ecdhe_private_key,
        password=None,
        backend=default_backend()
    )

    # Derive ECDHE shared secret
    print("Backend: Loading client's ECDHE public key...")
    client_ecdhe_public_key = serialization.load_pem_public_key(
        ecdhe_public_key_pem.encode(),
        backend=default_backend()
    )
    print("Backend: Performing hybrid key exchange...")
    ecdhe_shared_secret = ecdhe_private_key.exchange(ec.ECDH(), client_ecdhe_public_key)
    print(f"Backend: ECDHE shared secret calculated: {ecdhe_shared_secret.hex()}")

    # Decapsulate Kyber ciphertext
    print("Backend: Decapsulating Kyber ciphertext to obtain shared secret...")
    kyber_ciphertext = base64.b64decode(request.data.get("kyberCiphertext"))
    with oqs.KeyEncapsulation("Kyber512", secret_key=session.kyber_private_key) as server_kem:
        kyber_shared_secret = server_kem.decap_secret(kyber_ciphertext)
    print(f"Backend: Kyber shared secret obtained: {kyber_shared_secret.hex()}")

    # Combine ECDHE and Kyber shared secrets
    print("Backend: Combining ECDHE and Kyber shared secrets...")
    shared_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"hybrid-key",
    ).derive(ecdhe_shared_secret + kyber_shared_secret)
    print(f"Backend: Shared key for decryption: {shared_key.hex()}")

    # Decrypt data
    print("Backend: Decrypting the stored data...")
    plaintext = aes_decrypt(shared_key, data_entry.encrypted_data, data_entry.iv)
    print(f"Backend: Decrypted plaintext: {plaintext.decode()}")

    return Response({
        "encryptedData": base64.b64encode(data_entry.encrypted_data).decode(),
        "iv": base64.b64encode(data_entry.iv).decode(),
        "plaintext": plaintext.decode()
    }, status=status.HTTP_200_OK)



@api_view(['GET'])
def list_uploaded_data(request, session_id):
    """Lists all data uploaded for a specific session."""
    try:
        print(f"Retrieving session for ID: {session_id}")
        session = Session.objects.get(session_id=session_id, is_valid=True)
    except Session.DoesNotExist:
        print("Session does not exist or is invalid.")
        return Response({"error": "Invalid session"}, status=status.HTTP_400_BAD_REQUEST)

    if session.has_expired():
        print("Session has expired.")
        return Response({"error": "Session has expired"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        print("Retrieving uploaded data...")
        uploaded_data = UploadedData.objects.filter(session=session)
        serializer = UploadedDataSerializer(uploaded_data, many=True)
        print(f"Retrieved data: {serializer.data}")
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        print(f"Error during data listing: {e}")
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)