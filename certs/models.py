from django.db import models

class CertificateRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('verified', 'Verified'),
        ('failed', 'Failed'),
    ]

    domain = models.CharField(max_length=255)
    record_name = models.CharField(max_length=255)
    record_value = models.CharField(max_length=512)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    cert_path = models.TextField(blank=True, null=True)
    error_message = models.TextField(blank=True, null=True)
    s3_cert_key = models.CharField(max_length=512, blank=True, null=True)
    s3_key_key = models.CharField(max_length=512, blank=True, null=True)
    renewed_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(blank=True, null=True)
    issued_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"{self.domain} [{self.status}]"
