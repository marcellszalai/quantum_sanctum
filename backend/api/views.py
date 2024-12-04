from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import Session, UploadedData
from .serializers import SessionSerializer, UploadedDataSerializer
import oqs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64


# Helper Functions

def derive_symmetric_key(shared_secret):
    """Derive a symmetric key using HKDF."""
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b'session-key',
    ).derive(shared_secret)

# Modify the encryption to use consistent padding
def encrypt_with_aes256(aes_key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padded_data = padding.PKCS7(128).padder().update(plaintext.encode()) + padding.PKCS7(128).padder().finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(iv).decode('utf-8')


# Modify the decryption to handle padding properly
def decrypt_with_aes256(aes_key, encrypted_data_b64, iv_b64):
    ciphertext = base64.b64decode(encrypted_data_b64)
    iv = base64.b64decode(iv_b64)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    try:
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        return plaintext.decode('utf-8')
    except ValueError as e:
        print(f"Decryption failed: Padding error - {e}")
        return None




# Session Initiation
@api_view(['POST'])
def session_initiate(request):
    session_id = os.urandom(16).hex()

    # Generate Kyber key pair
    with oqs.KeyEncapsulation("Kyber512") as server_kem:
        kyber_public_key = server_kem.generate_keypair()
        kyber_private_key = server_kem.export_secret_key()

    # Generate ECDHE key pair
    ecdhe_private_key = ec.generate_private_key(ec.SECP256R1())
    ecdhe_public_key = ecdhe_private_key.public_key()

    # Derive the shared symmetric key using some shared secret (e.g., ECDHE or Kyber)
    shared_secret = b"some_shared_secret"  # Replace with actual shared secret
    shared_symmetric_key = derive_symmetric_key(shared_secret)

    # Store the session with the symmetric key
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
        ),
        shared_symmetric_key=shared_symmetric_key  # Ensure symmetric key is stored
    )

    serializer = SessionSerializer(session)
    return Response(serializer.data, status=status.HTTP_200_OK)


# Data Upload
@api_view(['POST'])
def data_upload(request):
    session_id = request.data.get('sessionId')
    encrypted_data_b64 = request.data.get('encryptedData')
    iv_b64 = request.data.get('iv')

    if not all([session_id, encrypted_data_b64, iv_b64]):
        return Response({'error': 'Missing data'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        session = Session.objects.get(session_id=session_id, is_valid=True)
        aes_key = session.shared_symmetric_key

        if aes_key is None:
            return Response({'error': 'AES key not found in session'}, status=status.HTTP_400_BAD_REQUEST)

        # Decrypt data
        decrypted_data = decrypt_with_aes256(aes_key, encrypted_data_b64, iv_b64)
        
        # Debugging: Check decrypted data
        print(f"Decrypted data: {decrypted_data}")  # Ensure the decrypted data is correct

        if decrypted_data:
            # Save decrypted data into the Session model
            session.uploaded_data = decrypted_data
            session.save()  # Save to the database

            print(f"Saved data: {session.uploaded_data}")  # Confirm data has been saved
        else:
            print("Decrypted data is empty or invalid")

        return Response({'message': 'Data uploaded successfully', 'decryptedData': decrypted_data}, status=status.HTTP_200_OK)

    except Session.DoesNotExist:
        return Response({'error': 'Invalid session'}, status=status.HTTP_400_BAD_REQUEST)
    except ValueError as e:
        return Response({'error': 'Decryption failed: Padding error'}, status=status.HTTP_400_BAD_REQUEST)




# Data Retrieval
@api_view(['POST'])
def data_retrieve(request):
    session_id = request.data.get('sessionId')
    record_id = request.data.get('recordId')

    if not all([session_id, record_id]):
        return Response({'error': 'Missing data'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        session = Session.objects.get(session_id=session_id, is_valid=True)

        # Option 1: Retrieve data from the Session model
        decrypted_data = session.uploaded_data

        # Option 2: Retrieve data from the separate UploadedData model
        # uploaded_data = UploadedData.objects.filter(session=session).order_by('-uploaded_at').first()
        # decrypted_data = uploaded_data.data if uploaded_data else None

        if decrypted_data:
            return Response({'decryptedData': decrypted_data}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'No data found for this session'}, status=status.HTTP_404_NOT_FOUND)

    except Session.DoesNotExist:
        return Response({'error': 'Invalid session'}, status=status.HTTP_400_BAD_REQUEST)