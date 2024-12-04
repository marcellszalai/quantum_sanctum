import os
import base64
import oqs
from django.core.exceptions import ImproperlyConfigured
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from .models import Session, UploadedData
from .serializers import SessionSerializer

# Load MASTER_KEY from environment (base64 encoded)
master_key_b64 = os.environ.get('MASTER_KEY')
if not master_key_b64:
    raise ImproperlyConfigured("MASTER_KEY environment variable must be set.")
master_key = base64.b64decode(master_key_b64)
if len(master_key) != 32:
    raise ImproperlyConfigured("MASTER_KEY must decode to 32 bytes.")

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

def derive_symmetric_key(shared_secret):
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b'session-key',
    ).derive(shared_secret)

@api_view(['POST'])
def session_initiate(request):
    # Server generates ephemeral keys
    session_id = os.urandom(16).hex()
    with oqs.KeyEncapsulation("Kyber512") as server_kem:
        kyber_public_key = server_kem.generate_keypair()
        kyber_private_key = server_kem.export_secret_key()

    ecdhe_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ecdhe_public_key = ecdhe_private_key.public_key()

    session = Session.objects.create(
        session_id=session_id,
        kyber_private_key=kyber_private_key,
        kyber_public_key=kyber_public_key,
        ecdhe_private_key=ecdhe_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ),
        ecdhe_public_key=ecdhe_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    session.set_expiration(minutes=5)
    serializer = SessionSerializer(session)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['POST'])
def session_finalize(request):
    # Client doesn't provide PQC data. The server simulates the client side internally.
    session_id = request.data.get('sessionId')
    if not session_id:
        return Response({'error': 'Missing sessionId'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        session = Session.objects.get(session_id=session_id, is_valid=True)
    except Session.DoesNotExist:
        return Response({'error': 'Invalid session'}, status=status.HTTP_400_BAD_REQUEST)

    if session.has_expired():
        return Response({'error': 'Session has expired'}, status=status.HTTP_400_BAD_REQUEST)

    # Simulate client side (server does both ends)
    # "Client" Kyber and ECDH keys
    with oqs.KeyEncapsulation("Kyber512", secret_key=None) as client_kem:
        # Encapsulate using the server's kyber_public_key
        ciphertext, kyber_ss = client_kem.encap_secret(bytes(session.kyber_public_key))

    server_private_key = serialization.load_pem_private_key(
        session.ecdhe_private_key, password=None, backend=default_backend()
    )
    server_public_key = serialization.load_pem_public_key(
        session.ecdhe_public_key, backend=default_backend()
    )

    # "Client" ECDHE keys
    client_ecdhe_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    client_ecdhe_public_key = client_ecdhe_private_key.public_key()
    ecdh_shared_secret = client_ecdhe_private_key.exchange(ec.ECDH(), server_public_key)

    # Decapsulate Kyber ciphertext with the server's private key
    with oqs.KeyEncapsulation("Kyber512", secret_key=bytes(session.kyber_private_key)) as server_kem:
        server_kyber_ss = server_kem.decap_secret(ciphertext)

    combined_secret = kyber_ss + ecdh_shared_secret
    shared_symmetric_key = derive_symmetric_key(combined_secret)

    # Encrypt shared_symmetric_key with MASTER_KEY
    enc_key, iv = aes_encrypt(master_key, shared_symmetric_key)
    session.encrypted_shared_symmetric_key = enc_key + iv

    # Remove ephemeral keys for forward secrecy
    session.kyber_private_key = b''
    session.kyber_public_key = b''
    session.ecdhe_private_key = b''
    session.ecdhe_public_key = b''

    session.save()
    return Response({'message': 'Session finalized successfully'}, status=status.HTTP_200_OK)

def get_shared_symmetric_key(session):
    """Retrieve and decrypt the session's symmetric key using MASTER_KEY."""
    if not session.encrypted_shared_symmetric_key:
        return None
    enc_data = session.encrypted_shared_symmetric_key
    enc_key = enc_data[:-16]
    iv = enc_data[-16:]
    return aes_decrypt(master_key, enc_key, iv)

@api_view(['POST'])
def data_upload(request):
    session_id = request.data.get('sessionId')
    plaintext = request.data.get('plaintext')  # now we assume client sends plaintext

    if not all([session_id, plaintext]):
        return Response({'error': 'Missing data'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        session = Session.objects.get(session_id=session_id, is_valid=True)
    except Session.DoesNotExist:
        return Response({'error': 'Invalid session'}, status=status.HTTP_400_BAD_REQUEST)

    if session.has_expired():
        return Response({'error': 'Session has expired'}, status=status.HTTP_400_BAD_REQUEST)

    aes_key = get_shared_symmetric_key(session)
    if aes_key is None:
        return Response({'error': 'Session key not established yet'}, status=status.HTTP_400_BAD_REQUEST)

    # Server encrypts data before storing
    ciphertext, iv = aes_encrypt(aes_key, plaintext.encode('utf-8'))
    data_record = UploadedData.objects.create(
        session=session,
        encrypted_data=ciphertext,
        iv=iv
    )

    return Response({'message': 'Data uploaded successfully', 'recordId': data_record.id}, status=status.HTTP_200_OK)

@api_view(['POST'])
def data_retrieve(request):
    session_id = request.data.get('sessionId')
    record_id = request.data.get('recordId')

    if not all([session_id, record_id]):
        return Response({'error': 'Missing data'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        session = Session.objects.get(session_id=session_id, is_valid=True)
    except Session.DoesNotExist:
        return Response({'error': 'Invalid session'}, status=status.HTTP_400_BAD_REQUEST)

    if session.has_expired():
        return Response({'error': 'Session has expired'}, status=status.HTTP_400_BAD_REQUEST)

    aes_key = get_shared_symmetric_key(session)
    if aes_key is None:
        return Response({'error': 'Session key not established yet'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        data_record = UploadedData.objects.get(id=record_id, session=session)
    except UploadedData.DoesNotExist:
        return Response({'error': 'No data found for this record'}, status=status.HTTP_404_NOT_FOUND)

    # Decrypt the stored data
    decrypted_plaintext = aes_decrypt(aes_key, data_record.encrypted_data, data_record.iv).decode('utf-8')
    return Response({'plaintext': decrypted_plaintext}, status=status.HTTP_200_OK)