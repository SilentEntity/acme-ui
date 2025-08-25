from django.core.management.base import BaseCommand
from certs.models import CertificateRequest
from django.utils import timezone
import subprocess
import os
import time
from certs.utils import upload_to_s3

class Command(BaseCommand):
    help = 'Auto-renew SSL certs and upload to S3 if renewed'

    def handle(self, *args, **kwargs):
        self.stdout.write("Running acme.sh auto-renew...")
        result = subprocess.run(["~/.acme.sh/acme.sh", "--renew-all", "--debug"], shell=True, capture_output=True, text=True)
        print(result.stdout)

        # Wait briefly in case files are being written
        time.sleep(2)

        for cert in CertificateRequest.objects.filter(status='verified'):
            domain = cert.domain
            cert_dir = os.path.join("certs/generated", domain)

            cert_path = os.path.join(cert_dir, "fullchain.cer")
            key_path = os.path.join(cert_dir, "privkey.key")

            if not os.path.exists(cert_path) or not os.path.exists(key_path):
                self.stderr.write(f"Missing files for {domain}")
                continue

            last_modified = timezone.datetime.fromtimestamp(os.path.getmtime(cert_path)).replace(tzinfo=timezone.utc)

            if not cert.renewed_at or last_modified > cert.renewed_at:
                self.stdout.write(f"Detected renewal for {domain}, uploading to S3...")

                try:
                    # Re-upload to S3
                    if cert.s3_cert_key:
                        upload_to_s3(cert_path, cert.s3_cert_key)
                    if cert.s3_key_key:
                        upload_to_s3(key_path, cert.s3_key_key)

                    cert.renewed_at = timezone.now()
                    cert.updated_at = timezone.now()
                    cert.save()

                    self.stdout.write(f"✅ {domain} renewed and updated.")
                except Exception as e:
                    self.stderr.write(f"❌ Error uploading renewed cert for {domain}: {e}")
