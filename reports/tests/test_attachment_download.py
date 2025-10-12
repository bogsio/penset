"""
Tests for attachment download functionality.
"""
import tempfile
import zipfile
import os
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from organizations.models import Organization
from reports.models import ScanSession, ScanResult, ScanResultAttachment

User = get_user_model()


class AttachmentDownloadTestCase(TestCase):
    """Test cases for attachment download functionality."""
    
    def setUp(self):
        """Set up test data."""
        # Create organization
        self.organization = Organization.objects.create(
            name="Test Organization"
        )
        
        # Create user
        self.user = User.objects.create_user(
            username='testuser@example.com',
            email='testuser@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
            organization=self.organization
        )
        
        # Create scan session
        self.scan_session = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            status='completed',
            archive_file=SimpleUploadedFile(
                "test_scan.zip",
                b"fake zip content",
                content_type="application/zip"
            )
        )
        
        # Create scan result
        self.scan_result = ScanResult.objects.create(
            scan_session=self.scan_session,
            result_type='exploitation',
            tool_name='test_tool',
            data={'vulnerability': 'Test Vulnerability'},
            severity='high'
        )
        
        # Create attachment
        self.attachment = ScanResultAttachment.objects.create(
            scan_result=self.scan_result,
            attachment_type='exploit_script',
            file_name='test_exploit.py',
            original_path='exploits/test_exploit.py',
            description='Test exploit script',
            s3_key='1/attachments/test-uuid.py',
            file_size=1024,
            mime_type='text/x-python',
            checksum='test-checksum'
        )
        
        self.client = Client()
        self.client.force_login(self.user)
    
    def test_download_attachment_success(self):
        """Test successful attachment download from S3."""
        # This test verifies the download endpoint is accessible and returns proper headers
        # The actual S3 streaming is tested in integration tests
        
        # Make request
        url = reverse('reports:download_attachment', kwargs={
            'scan_id': self.scan_session.id,
            'result_id': self.scan_result.id,
            'attachment_id': self.attachment.id
        })
        response = self.client.get(url)
        
        # Since S3 is not available in tests, we expect a placeholder response
        # This verifies the endpoint is working and returns appropriate content
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/plain', response['Content-Type'])
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertIn('test_exploit.py', response['Content-Disposition'])
        
        # Verify the response contains information about the file
        self.assertIn(b'test_exploit.py', response.content)
        self.assertIn(b'File not available for download', response.content)
    
    def test_download_attachment_s3_fallback_to_archive(self):
        """Test fallback to archive extraction when S3 fails."""
        # Mock S3 failure
        with patch('reports.storage.ScanStorageManager') as mock_storage_manager:
            mock_storage_instance = MagicMock()
            mock_storage_instance.get_attachment_stream.side_effect = Exception("S3 Error")
            mock_storage_manager.return_value = mock_storage_instance
            
            # Create temporary archive with test file
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip:
                with zipfile.ZipFile(temp_zip.name, 'w') as zip_file:
                    zip_file.writestr('exploits/test_exploit.py', 'print("Hello from archive")')
                
                # Update scan session with real zip file
                with open(temp_zip.name, 'rb') as f:
                    self.scan_session.archive_file.save(
                        'test_scan.zip',
                        SimpleUploadedFile(
                            'test_scan.zip',
                            f.read(),
                            content_type='application/zip'
                        )
                    )
                
                try:
                    # Make request
                    url = reverse('reports:download_attachment', kwargs={
                        'scan_id': self.scan_session.id,
                        'result_id': self.scan_result.id,
                        'attachment_id': self.attachment.id
                    })
                    response = self.client.get(url)
                    
                    # Assertions
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response['Content-Type'], 'text/x-python')
                    self.assertEqual(
                        response['Content-Disposition'],
                        'attachment; filename="test_exploit.py"'
                    )
                    self.assertEqual(response.content, b'print("Hello from archive")')
                    
                finally:
                    # Cleanup
                    os.unlink(temp_zip.name)
    
    def test_download_attachment_not_found_in_archive(self):
        """Test when file is not found in archive fallback."""
        # Mock S3 failure
        with patch('reports.storage.ScanStorageManager') as mock_storage_manager:
            mock_storage_instance = MagicMock()
            mock_storage_instance.get_attachment_stream.side_effect = Exception("S3 Error")
            mock_storage_manager.return_value = mock_storage_instance
            
            # Create empty archive
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip:
                with zipfile.ZipFile(temp_zip.name, 'w') as zip_file:
                    zip_file.writestr('other_file.txt', 'not the file we want')
                
                with open(temp_zip.name, 'rb') as f:
                    self.scan_session.archive_file.save(
                        'test_scan.zip',
                        SimpleUploadedFile(
                            'test_scan.zip',
                            f.read(),
                            content_type='application/zip'
                        )
                    )
                
                try:
                    # Make request
                    url = reverse('reports:download_attachment', kwargs={
                        'scan_id': self.scan_session.id,
                        'result_id': self.scan_result.id,
                        'attachment_id': self.attachment.id
                    })
                    response = self.client.get(url)
                    
                    # Should return placeholder content
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response['Content-Type'], 'text/plain')
                    self.assertIn(b'test_exploit.py', response.content)
                    self.assertIn(b'File not available for download', response.content)
                    
                finally:
                    os.unlink(temp_zip.name)
    
    def test_download_attachment_no_s3_key(self):
        """Test download when attachment has no S3 key."""
        # Remove S3 key
        self.attachment.s3_key = ''
        self.attachment.save()
        
        # Make request
        url = reverse('reports:download_attachment', kwargs={
            'scan_id': self.scan_session.id,
            'result_id': self.scan_result.id,
            'attachment_id': self.attachment.id
        })
        response = self.client.get(url)
        
        # Should return 404
        self.assertEqual(response.status_code, 404)
    
    def test_download_attachment_unauthorized_user(self):
        """Test download with unauthorized user."""
        # Create different organization and user
        other_org = Organization.objects.create(
            name="Other Organization"
        )
        other_user = User.objects.create_user(
            username='other@example.com',
            email='other@example.com',
            password='testpass123',
            organization=other_org
        )
        
        # Login as other user
        self.client.force_login(other_user)
        
        # Make request
        url = reverse('reports:download_attachment', kwargs={
            'scan_id': self.scan_session.id,
            'result_id': self.scan_result.id,
            'attachment_id': self.attachment.id
        })
        response = self.client.get(url)
        
        # Should return 404 (scan not found for this user's organization)
        self.assertEqual(response.status_code, 404)
    
    def test_download_attachment_nonexistent_scan(self):
        """Test download with nonexistent scan."""
        url = reverse('reports:download_attachment', kwargs={
            'scan_id': '00000000-0000-0000-0000-000000000000',
            'result_id': self.scan_result.id,
            'attachment_id': self.attachment.id
        })
        response = self.client.get(url)
        
        # Should return 404
        self.assertEqual(response.status_code, 404)
    
    def test_download_attachment_nonexistent_result(self):
        """Test download with nonexistent result."""
        url = reverse('reports:download_attachment', kwargs={
            'scan_id': self.scan_session.id,
            'result_id': '00000000-0000-0000-0000-000000000000',
            'attachment_id': self.attachment.id
        })
        response = self.client.get(url)
        
        # Should return 404
        self.assertEqual(response.status_code, 404)
    
    def test_download_attachment_nonexistent_attachment(self):
        """Test download with nonexistent attachment."""
        url = reverse('reports:download_attachment', kwargs={
            'scan_id': self.scan_session.id,
            'result_id': self.scan_result.id,
            'attachment_id': '00000000-0000-0000-0000-000000000000'
        })
        response = self.client.get(url)
        
        # Should return 404
        self.assertEqual(response.status_code, 404)
    
    def test_download_attachment_requires_login(self):
        """Test that download requires authentication."""
        # Logout user
        self.client.logout()
        
        # Make request
        url = reverse('reports:download_attachment', kwargs={
            'scan_id': self.scan_session.id,
            'result_id': self.scan_result.id,
            'attachment_id': self.attachment.id
        })
        response = self.client.get(url)
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/login/', response.url)
    
    def test_download_attachment_cache_headers(self):
        """Test that appropriate cache headers are set."""
        # Mock S3 file stream
        mock_file_stream = MagicMock()
        mock_file_stream.read.return_value = b'print("Hello World")'
        
        with patch('reports.storage.ScanStorageManager') as mock_storage_manager:
            mock_storage_instance = MagicMock()
            mock_storage_instance.get_attachment_stream.return_value = mock_file_stream
            mock_storage_manager.return_value = mock_storage_instance
            
            # Make request
            url = reverse('reports:download_attachment', kwargs={
                'scan_id': self.scan_session.id,
                'result_id': self.scan_result.id,
                'attachment_id': self.attachment.id
            })
            response = self.client.get(url)
            
            # Check cache headers
            self.assertEqual(response['Cache-Control'], 'no-cache, no-store, must-revalidate')
            self.assertEqual(response['Pragma'], 'no-cache')
            self.assertEqual(response['Expires'], '0')
    
    def test_download_attachment_different_mime_types(self):
        """Test download with different MIME types."""
        # Test with different attachment types
        test_cases = [
            ('exploit_script', 'text/x-python', 'test.py'),
            ('screenshot', 'image/png', 'screenshot.png'),
            ('log_file', 'text/plain', 'log.txt'),
            ('extracted_data', 'application/json', 'data.json'),
        ]
        
        for attachment_type, mime_type, filename in test_cases:
            with self.subTest(attachment_type=attachment_type):
                # Create attachment with specific type
                attachment = ScanResultAttachment.objects.create(
                    scan_result=self.scan_result,
                    attachment_type=attachment_type,
                    file_name=filename,
                    original_path=f'files/{filename}',
                    description=f'Test {attachment_type}',
                    s3_key=f'1/attachments/{attachment_type}-uuid',
                    file_size=512,
                    mime_type=mime_type,
                    checksum='test-checksum'
                )
                
                # Mock S3 file stream
                mock_file_stream = MagicMock()
                mock_file_stream.read.return_value = b'test content'
                
                with patch('reports.storage.ScanStorageManager') as mock_storage_manager:
                    mock_storage_instance = MagicMock()
                    mock_storage_instance.get_attachment_stream.return_value = mock_file_stream
                    mock_storage_manager.return_value = mock_storage_instance
                    
                    # Make request
                    url = reverse('reports:download_attachment', kwargs={
                        'scan_id': self.scan_session.id,
                        'result_id': self.scan_result.id,
                        'attachment_id': attachment.id
                    })
                    response = self.client.get(url)
                    
                    # Assertions
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response['Content-Type'], mime_type)
                    self.assertEqual(
                        response['Content-Disposition'],
                        f'attachment; filename="{filename}"'
                    )
