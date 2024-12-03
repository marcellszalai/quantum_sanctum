from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import Session, EncryptedRecord
from .serializers import SessionSerializer, EncryptedRecordSerializer
import oqs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import base64

# Session Initiation
@api_view(['POST'])
def session_initiate(request):
    session_id = os.urandom(16).hex()

    # Generate Kyber key pair
    with oqs.KeyEncapsulation("Kyber512") as server_kem:
        server_public_key = server_kem.generate_keypair()
        server_private_key = server_kem.export_secret_key()

    # Store keys in the Session model
    session = Session.objects.create(
        session_id=session_id,
        public_key=server_public_key,
        private_key=server_private_key
    )

    # Serialize session data
    serializer = SessionSerializer(session)
    return Response(serializer.data, status=status.HTTP_200_OK)

# Session Verification
@api_view(['POST'])
def session_verify(request):
    session_id = request.data.get('sessionId')
    is_valid = Session.objects.filter(session_id=session_id, is_valid=True).exists()
    return Response({'isValid': is_valid}, status=status.HTTP_200_OK)

# Data Upload
@api_view(['POST'])
def data_upload(request):
    session_id = request.data.get('sessionId')
    encrypted_data_b64 = request.data.get('encryptedData')
    salt = request.data.get('salt')
    iv = request.data.get('iv')
    data_hash = request.data.get('hash')
    kem_ciphertext_b64 = request.data.get('kemCiphertext')

    if not all([session_id, encrypted_data_b64, salt, iv, data_hash, kem_ciphertext_b64]):
        return Response({'error': 'Missing data'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        session = Session.objects.get(session_id=session_id, is_valid=True)

        # Decode the encrypted data and KEM ciphertext from base64
        encrypted_data = base64.b64decode(encrypted_data_b64)
        kem_ciphertext = base64.b64decode(kem_ciphertext_b64)

        # Store in database
        EncryptedRecord.objects.create(
            session=session,
            salt=salt,
            iv=iv,
            data_hash=data_hash,
            encrypted_data=encrypted_data,
            kem_ciphertext=kem_ciphertext
        )

        return Response({'message': 'Data uploaded successfully'}, status=status.HTTP_200_OK)
    except Session.DoesNotExist:
        return Response({'error': 'Invalid session'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Data Retrieval
@api_view(['POST'])
def data_retrieve(request):
    session_id = request.data.get('sessionId')
    record_id = request.data.get('recordId')

    if not all([session_id, record_id]):
        return Response({'error': 'Missing data'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        session = Session.objects.get(session_id=session_id, is_valid=True)
        record = EncryptedRecord.objects.get(id=record_id, session=session)

        # Decapsulate the shared secret using the server's private key and KEM ciphertext
        with oqs.KeyEncapsulation("Kyber512") as server_kem:
            server_private_key = session.private_key
            server_kem.import_secret_key(server_private_key)
            shared_secret = server_kem.decapsulate(record.kem_ciphertext)

        # The shared secret is used as the AES key
        aes_key = shared_secret[:32]

        # Decrypt the data
        decrypted_data_bytes = decrypt_with_aes256(aes_key, record.encrypted_data, record.iv)
        decrypted_data = decrypted_data_bytes.decode('utf-8')

        # Return data to client
        return Response({
            'data': decrypted_data,
            'salt': record.salt,
            'iv': record.iv,
            'hash': record.data_hash,
        }, status=status.HTTP_200_OK)
    except (Session.DoesNotExist, EncryptedRecord.DoesNotExist):
        return Response({'error': 'Invalid session or record'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Session End
@api_view(['POST'])
def session_end(request):
    session_id = request.data.get('sessionId')
    try:
        session = Session.objects.get(session_id=session_id)
        session.is_valid = False
        session.save()
        return Response({'message': 'Session ended successfully'}, status=status.HTTP_200_OK)
    except Session.DoesNotExist:
        return Response({'error': 'Invalid session'}, status=status.HTTP_400_BAD_REQUEST)

# Session Health
@api_view(['GET'])
def session_health(request):
    from django.utils import timezone
    return Response({
        'status': 'OK',
        'timeStamp': timezone.now().isoformat(),
    }, status=status.HTTP_200_OK)

# Encryption Functions
def encrypt_with_aes256(aes_key, plaintext):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    iv = cipher.iv
    return ct_bytes, iv

def decrypt_with_aes256(aes_key, ciphertext, iv_hex):
    iv = bytes.fromhex(iv_hex)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt