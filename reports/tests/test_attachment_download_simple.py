"""
Simple tests for attachment download functionality.
"""
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from organizations.models import Organization
from reports.models import ScanSession, ScanResult, ScanResultAttachment

User = get_user_model()


class SimpleAttachmentDownloadTestCase(TestCase):
    """Simple test cases for attachment download functionality."""
    
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
    
    def test_download_attachment_url_generation(self):
        """Test that the download URL is correctly generated."""
        url = reverse('reports:download_attachment', kwargs={
            'scan_id': self.scan_session.id,
            'result_id': self.scan_result.id,
            'attachment_id': self.attachment.id
        })
        
        expected_url = f'/scans/{self.scan_session.id}/results/{self.scan_result.id}/attachments/{self.attachment.id}/download/'
        self.assertEqual(url, expected_url)
    
    def test_attachment_model_properties(self):
        """Test attachment model properties."""
        # Test file extension
        self.assertEqual(self.attachment.file_extension, 'py')
        
        # Test display size
        self.assertEqual(self.attachment.display_size, '1.0 KB')
        
        # Test string representation
        expected_str = f"{self.attachment.file_name} ({self.attachment.attachment_type})"
        self.assertEqual(str(self.attachment), expected_str)

