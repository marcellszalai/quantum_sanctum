from django.db import models

# Session Model
class Session(models.Model):
    session_id = models.CharField(max_length=255, unique=True)
    kyber_private_key = models.BinaryField()
    kyber_public_key = models.BinaryField()
    ecdhe_private_key = models.BinaryField()
    ecdhe_public_key = models.BinaryField()
    shared_symmetric_key = models.BinaryField()
    
    # Field to indicate if the session is valid
    is_valid = models.BooleanField(default=True)
    
    # Field to store uploaded decrypted data (optional)
    uploaded_data = models.TextField(null=True, blank=True)
    
    # Field to store the creation timestamp
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.session_id


# Model to store uploaded data (optional if using a separate model)
class UploadedData(models.Model):
    session = models.ForeignKey(Session, on_delete=models.CASCADE)
    data = models.TextField()  # To store decrypted data
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Data for session {self.session.session_id}"