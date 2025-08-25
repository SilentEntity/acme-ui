from django.contrib import admin
from .models import CertificateRequest

@admin.register(CertificateRequest)
class CertificateRequestAdmin(admin.ModelAdmin):
    list_display = ('domain', 'status', 'created_at', 'updated_at')
    search_fields = ('domain', 'status')