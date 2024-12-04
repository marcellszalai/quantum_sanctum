from rest_framework import serializers
from .models import Session, UploadedData
import base64

class SessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Session
        fields = [
            'session_id',
            'created_at',
            'is_valid',
        ]

class UploadedDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedData
        fields = ['id', 'session', 'uploaded_at']