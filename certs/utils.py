import boto3
import os
from django.conf import settings

def upload_to_s3(local_path, s3_key):
    s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION
    )

    bucket = settings.AWS_STORAGE_BUCKET_NAME

    try:
        s3.upload_file(local_path, bucket, s3_key, ExtraArgs={'ACL': 'private'})
        s3_url = f"https://{bucket}.s3.{settings.AWS_REGION}.amazonaws.com/{s3_key}"
        return s3_url
    except Exception as e:
        raise Exception(f"S3 upload failed: {e}")