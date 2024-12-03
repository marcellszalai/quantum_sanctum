from rest_framework import serializers
from .models import Session, EncryptedRecord
import base64

class SessionSerializer(serializers.ModelSerializer):
    publicKey = serializers.SerializerMethodField()

    class Meta:
        model = Session
        fields = ['session_id', 'is_valid', 'created_at', 'publicKey']

    def get_publicKey(self, obj):
        return base64.b64encode(obj.public_key).decode('utf-8')

class EncryptedRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = EncryptedRecord
        fields = ['id', 'session', 'salt', 'iv', 'data_hash', 'encrypted_data', 'kem_ciphertext', 'created_at']