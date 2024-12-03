from django.db import models

class Session(models.Model):
    session_id = models.CharField(max_length=64, primary_key=True)
    is_valid = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    private_key = models.BinaryField()
    public_key = models.BinaryField()

class EncryptedRecord(models.Model):
    session = models.ForeignKey(Session, on_delete=models.CASCADE)
    salt = models.CharField(max_length=64)
    iv = models.CharField(max_length=32)  # Hex-encoded
    data_hash = models.CharField(max_length=64)  # SHA-256 hash
    encrypted_data = models.BinaryField()
    kem_ciphertext = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)