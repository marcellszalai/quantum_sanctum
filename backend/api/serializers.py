from rest_framework import serializers
from .models import Session, UploadedData
import base64

class SessionSerializer(serializers.ModelSerializer):
    kyberPublicKey = serializers.SerializerMethodField()
    ecdhePublicKey = serializers.SerializerMethodField()
    shared_symmetric_key = serializers.SerializerMethodField()

    class Meta:
        model = Session
        fields = ['session_id', 'created_at', 'kyberPublicKey', 'ecdhePublicKey', 'is_valid', 'uploaded_data', 'shared_symmetric_key']

    def get_kyberPublicKey(self, obj):
        return base64.b64encode(obj.kyber_public_key).decode('utf-8')

    def get_ecdhePublicKey(self, obj):
        return base64.b64encode(obj.ecdhe_public_key).decode('utf-8')

    def get_shared_symmetric_key(self, obj):
        return base64.b64encode(obj.shared_symmetric_key).decode('utf-8')


# Uploaded Data Serializer
class UploadedDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedData
        fields = ['session', 'data', 'uploaded_at']