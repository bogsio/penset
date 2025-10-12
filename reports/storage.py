import boto3
import hashlib
import mimetypes
from typing import Optional, BinaryIO
from django.conf import settings
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)


class ScanStorageManager:
    """Clean, extensible S3 storage management with UUID paths"""
    
    def __init__(self, scan_session):
        self.scan_session = scan_session
        self.base_path = f"scans/{scan_session.id}"
        self.s3_client = self._get_s3_client()
        self.bucket_name = settings.AWS_STORAGE_BUCKET_NAME
    
    def _get_s3_client(self):
        """Get S3 client with credentials"""
        return boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )
    
    def store_archive(self, file_obj: BinaryIO) -> str:
        """Store original archive"""
        key = f"{self.base_path}/archive.zip"
        try:
            self.s3_client.upload_fileobj(
                file_obj,
                self.bucket_name,
                key,
                ExtraArgs={
                    'ServerSideEncryption': 'AES256',
                    'ContentType': 'application/zip'
                }
            )
            logger.info(f"Archive stored at s3://{self.bucket_name}/{key}")
            return key
        except ClientError as e:
            logger.error(f"Error storing archive: {e}")
            raise
    
    def store_artifact(self, file_obj: BinaryIO, artifact_type: str, name: str, 
                      content_type: Optional[str] = None) -> str:
        """Store generated artifacts"""
        key = f"{self.base_path}/artifacts/{artifact_type}/{name}"
        
        if not content_type:
            content_type, _ = mimetypes.guess_type(name)
            if not content_type:
                content_type = 'application/octet-stream'
        
        try:
            self.s3_client.upload_fileobj(
                file_obj,
                self.bucket_name,
                key,
                ExtraArgs={
                    'ServerSideEncryption': 'AES256',
                    'ContentType': content_type
                }
            )
            logger.info(f"Artifact stored at s3://{self.bucket_name}/{key}")
            return key
        except ClientError as e:
            logger.error(f"Error storing artifact: {e}")
            raise
    
    def store_raw_output(self, content: str, tool_name: str, filename: str) -> str:
        """Store raw tool outputs"""
        key = f"{self.base_path}/raw_outputs/{tool_name}/{filename}"
        
        try:
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=content.encode('utf-8'),
                ServerSideEncryption='AES256',
                ContentType='application/json' if filename.endswith('.json') else 'text/plain'
            )
            logger.info(f"Raw output stored at s3://{self.bucket_name}/{key}")
            return key
        except ClientError as e:
            logger.error(f"Error storing raw output: {e}")
            raise
    
    def get_file(self, s3_key: str) -> bytes:
        """Retrieve file from S3"""
        try:
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=s3_key
            )
            return response['Body'].read()
        except ClientError as e:
            logger.error(f"Error retrieving file {s3_key}: {e}")
            raise
    
    def get_file_url(self, s3_key: str, expiration: int = 3600) -> str:
        """Generate presigned URL for file access"""
        try:
            url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': self.bucket_name, 'Key': s3_key},
                ExpiresIn=expiration
            )
            return url
        except ClientError as e:
            logger.error(f"Error generating presigned URL for {s3_key}: {e}")
            raise
    
    def delete_file(self, s3_key: str) -> bool:
        """Delete file from S3"""
        try:
            self.s3_client.delete_object(
                Bucket=self.bucket_name,
                Key=s3_key
            )
            logger.info(f"File deleted: s3://{self.bucket_name}/{s3_key}")
            return True
        except ClientError as e:
            logger.error(f"Error deleting file {s3_key}: {e}")
            return False
    
    def list_files(self, prefix: str = None) -> list:
        """List files in the scan directory"""
        if not prefix:
            prefix = self.base_path
        
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=prefix
            )
            
            files = []
            for obj in response.get('Contents', []):
                files.append({
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'last_modified': obj['LastModified']
                })
            
            return files
        except ClientError as e:
            logger.error(f"Error listing files with prefix {prefix}: {e}")
            return []
    
    def calculate_checksum(self, file_obj: BinaryIO) -> str:
        """Calculate SHA256 checksum of file"""
        file_obj.seek(0)
        content = file_obj.read()
        return hashlib.sha256(content).hexdigest()
    
    def get_file_size(self, s3_key: str) -> int:
        """Get file size from S3"""
        try:
            response = self.s3_client.head_object(
                Bucket=self.bucket_name,
                Key=s3_key
            )
            return response['ContentLength']
        except ClientError as e:
            logger.error(f"Error getting file size for {s3_key}: {e}")
            return 0
    
    def store_attachment(self, file_obj: BinaryIO, organization_id: str, attachment_uuid: str, 
                        original_filename: str, content_type: Optional[str] = None) -> str:
        """Store attachment file with organization-based path structure"""
        # Extract file extension from original filename
        file_extension = ""
        if '.' in original_filename:
            file_extension = f".{original_filename.split('.')[-1]}"
        
        # Create S3 key: {organization_id}/attachments/{attachment_uuid}.ext
        s3_key = f"{organization_id}/attachments/{attachment_uuid}{file_extension}"
        
        if not content_type:
            content_type, _ = mimetypes.guess_type(original_filename)
            if not content_type:
                content_type = 'application/octet-stream'
        
        try:
            self.s3_client.upload_fileobj(
                file_obj,
                self.bucket_name,
                s3_key,
                ExtraArgs={
                    'ServerSideEncryption': 'AES256',
                    'ContentType': content_type,
                    'Metadata': {
                        'original_filename': original_filename,
                        'organization_id': organization_id
                    }
                }
            )
            logger.info(f"Attachment stored at s3://{self.bucket_name}/{s3_key}")
            return s3_key
        except ClientError as e:
            logger.error(f"Error storing attachment: {e}")
            raise
    
    def get_attachment_stream(self, s3_key: str):
        """Get attachment file stream from S3"""
        try:
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=s3_key
            )
            return response['Body']
        except ClientError as e:
            logger.error(f"Error retrieving attachment {s3_key}: {e}")
            raise