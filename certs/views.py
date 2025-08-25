from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
import base64
import random
import dns.resolver
import subprocess
import os
from django.conf import settings
from .models import CertificateRequest
from .utils import upload_to_s3
from django.http import HttpResponseRedirect, Http404
import boto3
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from django.contrib.auth.decorators import login_required

from django.db.models import F, ExpressionWrapper, DurationField
from django.utils import timezone
from datetime import timedelta 

ACME_SH_PATH = os.path.expanduser("~/.acme.sh/acme.sh")  # adjust if needed
CERT_OUTPUT_DIR = os.path.join(settings.BASE_DIR, "certs/generated")

os.makedirs(CERT_OUTPUT_DIR, exist_ok=True)

# Store challenge data in memory (for demo only)
challenge_store = {}

@login_required
def index(request):
    return render(request, 'certs/index.html')

@login_required
def dashboard(request):
    certs = CertificateRequest.objects.filter(status='verified')

    # Filter expiring soon if requested
    if request.GET.get('expiring') == '1':
        certs = certs.filter(expires_at__lte=timezone.now() + timedelta(days=15))

    # Calculate days left (optional optimization)
    for cert in certs:
        if cert.expires_at:
            cert.days_left = (cert.expires_at - timezone.now()).days
        else:
            cert.days_left = None

    return render(request, 'certs/dashboard.html', {'certs': certs})

# @csrf_exempt
# def generate_challenge(request):
#     if request.method == 'POST':
#         domain = request.POST.get('domain')
#         challenge_value = base64.urlsafe_b64encode(
#             str(random.random()).encode()
#         ).decode()[:32]
#         record_name = f"_acme-challenge.{domain}"

#         # Store challenge
#         challenge_store[domain] = {
#             'record_name': record_name,
#             'record_value': challenge_value,
#             'verified': False
#         }

#         return render(request, 'certs/index.html', {
#             'domain': domain,
#             'record_name': record_name,
#             'record_value': challenge_value
#         })
#     return redirect('index')

# @csrf_exempt
# def verify_dns(request):
#     domain = request.POST.get('domain')
#     challenge = challenge_store.get(domain)
#     if challenge:
#         challenge['verified'] = True
#         return render(request, 'certs/index.html', {
#             'domain': domain,
#             'record_name': challenge['record_name'],
#             'record_value': challenge['record_value'],
#             'certificate': '-----BEGIN CERTIFICATE-----\nFAKE-CERTIFICATE\n-----END CERTIFICATE-----'
#         })
#     return redirect('index')

@csrf_exempt
def generate_challenge(request):
    if request.method == 'POST':
        domain = request.POST.get('domain').strip().lower()
        challenge_value = base64.urlsafe_b64encode(
            str(random.random()).encode()
        ).decode()[:32]
        record_name = f"_acme-challenge.{domain}"

        cert_req, created = CertificateRequest.objects.update_or_create(
            domain=domain,
            defaults={
                'record_name': record_name,
                'record_value': challenge_value,
                'status': 'pending',
                'error_message': '',
                'cert_path': '',
            }
        )

        return render(request, 'certs/index.html', {
            'domain': domain,
            'record_name': record_name,
            'record_value': challenge_value
        })

    return redirect('index')


def dns_txt_record_exists(name, expected_value):
    try:
        answers = dns.resolver.resolve(name, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                if txt_string.decode() == expected_value:
                    return True
    except Exception as e:
        print(f"[DNS CHECK ERROR]: {e}")
    return False


# @csrf_exempt
# def verify_dns(request):
#     domain = request.POST.get('domain')
#     challenge = challenge_store.get(domain)
#     if not challenge:
#         return redirect('index')

#     record_name = challenge['record_name']
#     record_value = challenge['record_value']

#     if not dns_txt_record_exists(record_name, record_value):
#         return render(request, 'certs/index.html', {
#             'domain': domain,
#             'record_name': record_name,
#             'record_value': record_value,
#             'error': 'DNS record not found. Please wait for DNS to propagate and try again.'
#         })

#     # If DNS is correct, request cert via acme.sh
#     cert_dir = os.path.join(CERT_OUTPUT_DIR, domain)
#     os.makedirs(cert_dir, exist_ok=True)

#     try:
#         cmd = [
#             ACME_SH_PATH,
#             "--issue",
#             "--dns",  # Manual DNS challenge already satisfied
#             "-d", domain,
#             "--debug",
#             "--cert-home", cert_dir
#         ]

#         result = subprocess.run(cmd, capture_output=True, text=True)
#         print(result.stdout)

#         # Check for cert success
#         cert_path = os.path.join(cert_dir, domain, "fullchain.cer")
#         if not os.path.exists(cert_path):
#             raise Exception("Certificate not found. Something went wrong.")

#         with open(cert_path, "r") as f:
#             cert_content = f.read()

#         challenge['verified'] = True

#         return render(request, 'certs/index.html', {
#             'domain': domain,
#             'record_name': record_name,
#             'record_value': record_value,
#             'certificate': cert_content
#         })

#     except Exception as e:
#         return render(request, 'certs/index.html', {
#             'domain': domain,
#             'record_name': record_name,
#             'record_value': record_value,
#             'error': str(e)
#         })

def parse_cert_dates(cert_path):
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert.not_valid_before, cert.not_valid_after

@csrf_exempt
def verify_dns(request):
    domain = request.POST.get('domain')
    try:
        cert_req = CertificateRequest.objects.get(domain=domain)
    except CertificateRequest.DoesNotExist:
        return redirect('index')

    record_name = cert_req.record_name
    record_value = cert_req.record_value

    if not dns_txt_record_exists(record_name, record_value):
        cert_req.status = 'pending'
        cert_req.error_message = 'DNS record not found.'
        cert_req.save()

        return render(request, 'certs/index.html', {
            'domain': domain,
            'record_name': record_name,
            'record_value': record_value,
            'error': 'DNS record not found. Please wait for DNS to propagate and try again.'
        })

    # Run acme.sh
    cert_dir = os.path.join(CERT_OUTPUT_DIR, domain)
    os.makedirs(cert_dir, exist_ok=True)

    try:
        cmd = [
            ACME_SH_PATH,
            "--issue",
            "--dns",
            "-d", domain,
            "--cert-home", cert_dir
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)

        base_path = os.path.join(cert_dir, domain)
        cert_path = os.path.join(base_path, "fullchain.cer")
        key_path = os.path.join(base_path, "privkey.key")

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            raise Exception("Certificate or key file missing")
        
        issued_at, expires_at = parse_cert_dates(cert_path)

        cert_req.issued_at = issued_at
        cert_req.expires_at = expires_at

        # Upload both to S3
        cert_s3_key = f"certs/{domain}/fullchain.cer"
        key_s3_key = f"certs/{domain}/privkey.key"

        # s3_cert_url = upload_to_s3(cert_path, cert_s3_key)
        # s3_key_url = upload_to_s3(key_path, key_s3_key)

        upload_to_s3(cert_path, cert_s3_key)
        upload_to_s3(key_path, key_s3_key)

        cert_req.s3_cert_key = cert_s3_key
        cert_req.s3_key_key = key_s3_key

        with open(cert_path, "r") as f:
            cert_content = f.read()

        cert_req.status = 'verified'
        cert_req.cert_path = cert_path
        cert_req.error_message = ''
        cert_req.save()

        return render(request, 'certs/index.html', {
            'domain': domain,
            'record_name': record_name,
            'record_value': record_value,
            'certificate': cert_content,
            's3_cert_url': s3_cert_url,
            's3_key_url': s3_key_url
        })

    except Exception as e:
        cert_req.status = 'failed'
        cert_req.error_message = str(e)
        cert_req.save()

        return render(request, 'certs/index.html', {
            'domain': domain,
            'record_name': record_name,
            'record_value': record_value,
            'error': str(e)
        })
    

def generate_presigned_url(s3_key, expiration=300):
    s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION
    )
    try:
        response = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': settings.AWS_STORAGE_BUCKET_NAME, 'Key': s3_key},
            ExpiresIn=expiration
        )
        return response
    except Exception as e:
        print(f"[S3 SIGN ERROR] {e}")
        return None


def download_cert(request, domain, filetype):
    try:
        cert = CertificateRequest.objects.get(domain=domain, status='verified')
    except CertificateRequest.DoesNotExist:
        raise Http404("Certificate not found")

    if filetype == 'cert':
        s3_key = cert.s3_cert_key
    elif filetype == 'key':
        s3_key = cert.s3_key_key
    else:
        raise Http404("Invalid file type")

    url = generate_presigned_url(s3_key)
    if url:
        return HttpResponseRedirect(url)
    raise Http404("Unable to generate signed URL")