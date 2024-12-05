from django.db import models
from django.utils import timezone
from datetime import timedelta

class Session(models.Model):
    session_id = models.CharField(max_length=255, unique=True)
    ecdhe_private_key = models.BinaryField(blank=True, null=True)  # Server's ECDHE private key
    ecdhe_public_key = models.BinaryField(blank=True, null=True)  # Server's ECDHE public key
    kyber_public_key = models.BinaryField(blank=True, null=True)  # Kyber public key
    kyber_private_key = models.BinaryField(blank=True, null=True)  # Kyber private key
    is_valid = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=None, null=True, blank=True)

    def set_expiration(self, minutes=5):
        self.expires_at = self.created_at + timedelta(minutes=minutes)
        self.save()

    def has_expired(self):
        if self.expires_at is None:
            return False
        return timezone.now() > self.expires_at

    def __str__(self):
        return self.session_id


class UploadedData(models.Model):
    session = models.ForeignKey(Session, on_delete=models.CASCADE)
    encrypted_data = models.BinaryField()
    iv = models.BinaryField()
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Data for session {self.session.session_id}"