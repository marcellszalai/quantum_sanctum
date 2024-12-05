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
from .serializers import SessionSerializer, UploadedDataSerializer

# Helper Functions
def aes_encrypt(key, plaintext_bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext_bytes) + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext, iv


def aes_decrypt(key, ciphertext, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext

# Views
@api_view(['POST'])
def session_initiate(request):
    """Initiates a session and provides ECDHE public key to the client."""
    session_id = os.urandom(16).hex()

    # Generate ECDHE keys (server-side)
    ecdhe_private_key = ec.generate_private_key(ec.SECP256R1())
    ecdhe_public_key = ecdhe_private_key.public_key()

    # Generate Kyber keys for post-quantum storage
    with oqs.KeyEncapsulation("Kyber512") as server_kem:
        kyber_public_key = server_kem.generate_keypair()
        kyber_private_key = server_kem.export_secret_key()

    # Store ECDHE private key and Kyber keys in the session
    session = Session.objects.create(
        session_id=session_id,
        ecdhe_private_key=ecdhe_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        kyber_public_key=kyber_public_key,
        kyber_private_key=kyber_private_key,
    )
    session.set_expiration(minutes=5)

    # Send ECDHE public key and session ID to the client
    serialized_public_key = ecdhe_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    response_data = {
        "sessionId": session_id,
        "ecdhePublicKey": serialized_public_key.decode(),
    }
    return Response(response_data, status=status.HTTP_200_OK)


@api_view(['POST'])
def data_upload(request):
    """Receives client-encrypted data, decrypts it, and re-encrypts it using Kyber."""
    session_id = request.data.get("sessionId")
    client_public_key_pem = request.data.get("clientPublicKey")
    encrypted_data = base64.b64decode(request.data.get("encryptedData"))
    iv = base64.b64decode(request.data.get("iv"))

    if not all([session_id, client_public_key_pem, encrypted_data, iv]):
        return Response({"error": "Missing data"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        session = Session.objects.get(session_id=session_id, is_valid=True)
    except Session.DoesNotExist:
        return Response({"error": "Invalid session"}, status=status.HTTP_400_BAD_REQUEST)

    if session.has_expired():
        return Response({"error": "Session has expired"}, status=status.HTTP_400_BAD_REQUEST)

    # Derive shared secret using ECDHE
    server_private_key = serialization.load_pem_private_key(
        session.ecdhe_private_key, password=None, backend=default_backend()
    )
    client_public_key = serialization.load_pem_public_key(
        client_public_key_pem.encode(), backend=default_backend()
    )
    shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

    # Derive symmetric key from shared secret
    symmetric_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"session-key",
    ).derive(shared_secret)

    # Decrypt client data
    plaintext = aes_decrypt(symmetric_key, encrypted_data, iv)

    # Encrypt plaintext using Kyber-derived key
    with oqs.KeyEncapsulation("Kyber512", secret_key=session.kyber_private_key) as server_kem:
        kyber_key = server_kem.export_secret_key()[:32]
    kyber_cipher = Cipher(algorithms.AES(kyber_key), modes.CBC(iv), backend=default_backend())
    encryptor = kyber_cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    encrypted_data_kyber = encryptor.update(padded_plaintext) + encryptor.finalize()
    print("encrypted data kyber: ")
    print(encrypted_data_kyber)

    # Store Kyber-encrypted data
    UploadedData.objects.create(session=session, encrypted_data=encrypted_data_kyber, iv=iv)

    return Response({"message": "Data uploaded and stored securely."}, status=status.HTTP_200_OK)


@api_view(['GET'])
def list_uploaded_data(request, session_id):
    """Lists all data uploaded for a specific session."""
    try:
        session = Session.objects.get(session_id=session_id, is_valid=True)
    except Session.DoesNotExist:
        return Response({"error": "Invalid session"}, status=status.HTTP_400_BAD_REQUEST)

    if session.has_expired():
        return Response({"error": "Session has expired"}, status=status.HTTP_400_BAD_REQUEST)

    uploaded_data = UploadedData.objects.filter(session=session)
    serializer = UploadedDataSerializer(uploaded_data, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['POST'])
def retrieve_data(request):
    """Retrieves a specific data entry and returns its plaintext."""
    session_id = request.data.get("sessionId")
    data_id = request.data.get("dataId")
    client_public_key_pem = request.data.get("clientPublicKey")

    if not all([session_id, data_id, client_public_key_pem]):
        return Response({"error": "Missing data"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        session = Session.objects.get(session_id=session_id, is_valid=True)
    except Session.DoesNotExist:
        return Response({"error": "Invalid session"}, status=status.HTTP_400_BAD_REQUEST)

    if session.has_expired():
        return Response({"error": "Session has expired"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        data_entry = UploadedData.objects.get(id=data_id, session=session)
    except UploadedData.DoesNotExist:
        return Response({"error": "No data found for this ID in this session"}, status=status.HTTP_404_NOT_FOUND)

    # Derive shared secret using ECDHE
    server_private_key = serialization.load_pem_private_key(
        session.ecdhe_private_key, password=None, backend=default_backend()
    )
    client_public_key = serialization.load_pem_public_key(
        client_public_key_pem.encode(), backend=default_backend()
    )
    shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

    # Derive symmetric key from shared secret
    symmetric_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"session-key",
    ).derive(shared_secret)

    # Decrypt the stored data using Kyber-derived key
    with oqs.KeyEncapsulation("Kyber512", secret_key=session.kyber_private_key) as server_kem:
        kyber_key = server_kem.export_secret_key()[:32]
    kyber_cipher = Cipher(algorithms.AES(kyber_key), modes.CBC(data_entry.iv), backend=default_backend())
    decryptor = kyber_cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_padded_data = decryptor.update(data_entry.encrypted_data) + decryptor.finalize()
    plaintext = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # Encrypt the plaintext with the ECDHE-derived symmetric key
    encrypted_data, iv = aes_encrypt(symmetric_key, plaintext)  # Pass plaintext as bytes

    return Response({
        "encryptedData": base64.b64encode(encrypted_data).decode(),
        "iv": base64.b64encode(iv).decode(),
    }, status=status.HTTP_200_OK)