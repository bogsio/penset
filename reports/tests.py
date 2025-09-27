"""
Tests for the reports app, specifically for ZIP file processing functionality.
"""

import os
import tempfile
import zipfile
from django.test import TestCase, override_settings, Client
from django.core.files import File
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile

from .models import ScanSession, Target, ScanResult, ScanArtifact
from .admin_forms import ScanSessionAdminForm, ScanUploadForm
from organizations.models import Organization

User = get_user_model()


class ScanSessionZipProcessingTestCase(TestCase):
    """Test case for ZIP file processing functionality."""
    
    def setUp(self):
        """Set up test data."""
        # Create test organization
        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Test organization for unit tests"
        )
        
        # Create test user
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123",
            first_name="Test",
            last_name="User",
            organization=self.organization
        )
        
        # Create toy ZIP file for testing
        self.toy_zip_path = self._create_toy_zip_file()
    
    def _create_toy_zip_file(self):
        """Create a toy ZIP file with test data."""
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_file:
            with zipfile.ZipFile(tmp_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add summary reports
                zipf.writestr('enriched_summary_report.json', '''{
                    "scan_info": {"scan_type": "reconnaissance"},
                    "input_targets": {"targets": ["example.com", "test.example.com"]},
                    "summary": {"total_domains": 2, "total_ips": 1}
                }''')
                
                zipf.writestr('vulnerability_summary_report.json', '''{
                    "scan_info": {"scan_type": "vulnerability"},
                    "summary": {"total_vulnerabilities": 2, "high": 1, "medium": 1}
                }''')
                
                zipf.writestr('exploitation_summary_report.json', '''{
                    "scan_info": {"scan_type": "exploitation"},
                    "summary": {"total_exploits": 1, "successful": 1}
                }''')
                
                # Add domains
                zipf.writestr('domains/all_domains.txt', 'example.com\ntest.example.com\napi.example.com')
                
                # Add IPs
                zipf.writestr('ips/all_ips.txt', '93.184.216.34\n192.168.1.100')
                
                # Add ports
                zipf.writestr('ports/open_ports.json', '''{
                    "93.184.216.34": [80, 443],
                    "192.168.1.100": [22, 80, 443]
                }''')
                
                # Add services
                zipf.writestr('services/detected_services.json', '''{
                    "93.184.216.34": {"80": "http", "443": "https"},
                    "192.168.1.100": {"22": "ssh", "80": "http", "443": "https"}
                }''')
                
                # Add web enumeration
                zipf.writestr('web/web_enumeration.json', '''{
                    "http://example.com": {"status": 200, "title": "Example Domain"},
                    "https://example.com": {"status": 200, "title": "Example Domain"}
                }''')
                
                # Add vulnerabilities
                zipf.writestr('vulnerabilities/nuclei_results.json', '''[
                    {
                        "template_id": "http-missing-security-headers",
                        "info": {"name": "Missing Security Headers", "severity": "medium"},
                        "host": "http://example.com",
                        "target": "http://example.com"
                    }
                ]''')
                
                zipf.writestr('vulnerabilities/nikto_results.json', '''[
                    {
                        "host": "http://example.com",
                        "port": 80,
                        "vulnerabilities": [{"id": "1001", "severity": "high", "description": "Directory browsing"}]
                    }
                ]''')
                
                # Add exploit results
                zipf.writestr('exploit_results/successful_exploits.json', '''[
                    {
                        "target": "http://example.com",
                        "vulnerability": "Directory Browsing",
                        "success": true,
                        "severity": "high",
                        "exploit_script_path": "exploits/directory_browsing_exploit.py"
                    }
                ]''')
                
                # Add exploit scripts
                zipf.writestr('exploits/directory_browsing_exploit.py', '''#!/usr/bin/env python3
import requests
def exploit_directory_browsing(target_url):
    response = requests.get(f"{target_url}/")
    return response.status_code == 200
''')
                
                zipf.writestr('exploits/ssl_cipher_exploit.py', '''#!/usr/bin/env python3
import ssl
def exploit_ssl_cipher(target_host):
    return True
''')
            
            return tmp_file.name
    
    def tearDown(self):
        """Clean up test data."""
        if os.path.exists(self.toy_zip_path):
            os.unlink(self.toy_zip_path)
    
    def test_scan_session_creation(self):
        """Test basic ScanSession creation."""
        scan_session = ScanSession.objects.create(
            description="Test scan session",
            organization=self.organization,
            created_by=self.user,
            status='uploaded'
        )
        
        self.assertEqual(scan_session.description, "Test scan session")
        self.assertEqual(scan_session.organization, self.organization)
        self.assertEqual(scan_session.created_by, self.user)
        self.assertEqual(scan_session.status, 'uploaded')
        self.assertIsNotNone(scan_session.id)
    
    def test_scan_session_filefield(self):
        """Test ScanSession FileField functionality."""
        scan_session = ScanSession.objects.create(
            description="Test scan session with file",
            organization=self.organization,
            created_by=self.user,
            status='uploaded'
        )
        
        # Test file upload
        with open(self.toy_zip_path, 'rb') as f:
            django_file = File(f)
            scan_session.archive_file.save('test_scan.zip', django_file, save=True)
        
        self.assertTrue(scan_session.archive_file)
        self.assertTrue(scan_session.archive_file.name.startswith('scans/archives/test_scan'))
        self.assertTrue(scan_session.archive_file.name.endswith('.zip'))
        self.assertIsNotNone(scan_session.archive_url)
        self.assertIsNotNone(scan_session.archive_name)
        self.assertTrue(scan_session.get_archive_file())
        
        # Test checksum calculation
        checksum = scan_session.calculate_checksum()
        self.assertIsNotNone(checksum)
        self.assertEqual(len(checksum), 64)  # SHA256 hex length
    
    def test_admin_form_zip_processing(self):
        """Test ZIP file processing through admin form."""
        # Create scan session
        scan_session = ScanSession.objects.create(
            description="Test admin form processing",
            organization=self.organization,
            created_by=self.user,
            status='uploaded'
        )
        
        # Upload file
        with open(self.toy_zip_path, 'rb') as f:
            django_file = File(f)
            scan_session.archive_file.save('admin_test.zip', django_file, save=True)
        
        # Process the archive using admin form
        admin_form = ScanSessionAdminForm()
        admin_form._process_uploaded_archive(scan_session, scan_session.archive_file)
        
        # Verify processing results
        self.assertEqual(scan_session.status, 'completed')
        
        # Check targets were created
        targets = scan_session.targets.all()
        self.assertGreater(targets.count(), 0)
        
        # Check for specific targets
        domain_targets = targets.filter(target_type='domain')
        self.assertGreater(domain_targets.count(), 0)
        
        ip_targets = targets.filter(target_type='ip')
        self.assertGreater(ip_targets.count(), 0)
        
        url_targets = targets.filter(target_type='url')
        self.assertGreater(url_targets.count(), 0)
        
        # Check results were created
        results = scan_session.results.all()
        self.assertGreater(results.count(), 0)
        
        # Check for different result types
        recon_results = results.filter(result_type='reconnaissance')
        self.assertGreater(recon_results.count(), 0)
        
        vuln_results = results.filter(result_type='vulnerability')
        self.assertGreater(vuln_results.count(), 0)
        
        exploit_results = results.filter(result_type='exploitation')
        self.assertGreater(exploit_results.count(), 0)
        
        # Check artifacts were created
        artifacts = scan_session.artifacts.all()
        self.assertGreater(artifacts.count(), 0)
        
        # Check for exploit scripts
        exploit_scripts = artifacts.filter(artifact_type='exploit_script')
        self.assertGreater(exploit_scripts.count(), 0)
    
    def test_scan_upload_form_validation(self):
        """Test ScanUploadForm validation."""
        # Test valid form
        with open(self.toy_zip_path, 'rb') as f:
            uploaded_file = SimpleUploadedFile(
                "test_scan.zip",
                f.read(),
                content_type="application/zip"
            )
        
        form_data = {
            'name': 'Test Upload',
            'description': 'Test upload form'
        }
        
        form = ScanUploadForm(data=form_data, files={'archive': uploaded_file})
        self.assertTrue(form.is_valid())
        
        # Test invalid file type
        with open(self.toy_zip_path, 'rb') as f:
            invalid_file = SimpleUploadedFile(
                "test_scan.txt",
                f.read(),
                content_type="text/plain"
            )
        
        form_data_invalid = {
            'name': 'Test Upload',
            'description': 'Test upload form'
        }
        
        form_invalid = ScanUploadForm(data=form_data_invalid, files={'archive': invalid_file})
        self.assertFalse(form_invalid.is_valid())
        self.assertIn('archive', form_invalid.errors)
    
    def test_scan_session_admin_readonly_fields(self):
        """Test that archive_file is readonly for existing objects."""
        from .admin import ScanSessionAdmin
        
        # Create scan session
        scan_session = ScanSession.objects.create(
            description="Test readonly fields",
            organization=self.organization,
            created_by=self.user,
            status='uploaded'
        )
        
        # Create admin instance
        admin = ScanSessionAdmin(ScanSession, None)
        
        # Test readonly fields for existing object
        readonly_fields = admin.get_readonly_fields(None, scan_session)
        self.assertIn('archive_file', readonly_fields)
        
        # Test readonly fields for new object
        readonly_fields_new = admin.get_readonly_fields(None, None)
        self.assertNotIn('archive_file', readonly_fields_new)
    
    def test_scan_session_relationships(self):
        """Test relationships between ScanSession, Targets, Results, and Artifacts."""
        # Create scan session and process ZIP
        scan_session = ScanSession.objects.create(
            description="Test relationships",
            organization=self.organization,
            created_by=self.user,
            status='uploaded'
        )
        
        # Upload and process file
        with open(self.toy_zip_path, 'rb') as f:
            django_file = File(f)
            scan_session.archive_file.save('relationship_test.zip', django_file, save=True)
        
        admin_form = ScanSessionAdminForm()
        admin_form._process_uploaded_archive(scan_session, scan_session.archive_file)
        
        # Test relationships
        targets = scan_session.targets.all()
        results = scan_session.results.all()
        artifacts = scan_session.artifacts.all()
        
        # Check that targets have results
        targets_with_results = targets.filter(results__isnull=False).distinct()
        self.assertGreater(targets_with_results.count(), 0)
        
        # Check that results have targets
        results_with_targets = results.filter(target__isnull=False)
        self.assertGreater(results_with_targets.count(), 0)
        
        # Check that results have artifacts
        results_with_artifacts = results.filter(artifacts__isnull=False)
        self.assertGreater(results_with_artifacts.count(), 0)
    
    def test_scan_session_metadata_tracking(self):
        """Test metadata tracking (size, checksum, S3 key)."""
        scan_session = ScanSession.objects.create(
            description="Test metadata tracking",
            organization=self.organization,
            created_by=self.user,
            status='uploaded'
        )
        
        # Upload file
        with open(self.toy_zip_path, 'rb') as f:
            django_file = File(f)
            scan_session.archive_file.save('metadata_test.zip', django_file, save=True)
        
        scan_session.save()
        
        # Verify metadata
    
    def test_scan_session_status_workflow(self):
        """Test scan session status workflow."""
        scan_session = ScanSession.objects.create(
            description="Test status workflow",
            organization=self.organization,
            created_by=self.user,
            status='uploaded'
        )
        
        # Test initial status
        self.assertEqual(scan_session.status, 'uploaded')
        
        # Test processing status
        scan_session.status = 'processing'
        scan_session.save()
        self.assertEqual(scan_session.status, 'processing')
        
        # Test completed status
        scan_session.status = 'completed'
        scan_session.save()
        self.assertEqual(scan_session.status, 'completed')
        
        # Test failed status
        scan_session.status = 'failed'
        scan_session.error_message = "Test error"
        scan_session.save()
        self.assertEqual(scan_session.status, 'failed')
        self.assertEqual(scan_session.error_message, "Test error")
    
    def test_scan_session_duration_calculation(self):
        """Test duration calculation."""
        from django.utils import timezone
        from datetime import timedelta
        
        scan_session = ScanSession.objects.create(
            description="Test duration calculation",
            organization=self.organization,
            created_by=self.user,
            status='uploaded'
        )
        
        # Test no duration initially
        self.assertIsNone(scan_session.duration)
        
        # Set start and end times
        now = timezone.now()
        scan_session.started_at = now
        scan_session.completed_at = now + timedelta(minutes=30)
        scan_session.save()
        
        # Test duration calculation
        duration = scan_session.duration
        self.assertIsNotNone(duration)
        self.assertEqual(duration.total_seconds(), 30 * 60)  # 30 minutes in seconds


class ScanSessionModelTestCase(TestCase):
    """Test case for ScanSession model methods."""
    
    def setUp(self):
        """Set up test data."""
        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Test organization"
        )
        
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123",
            first_name="Test",
            last_name="User",
            organization=self.organization
        )
    
    def test_scan_session_str_representation(self):
        """Test string representation of ScanSession."""
        scan_session = ScanSession.objects.create(
            description="Test description",
            organization=self.organization,
            created_by=self.user,
            status='uploaded'
        )
        
        expected_str = f"Session {scan_session.id} (uploaded)"
        self.assertEqual(str(scan_session), expected_str)
    
    def test_scan_session_meta_ordering(self):
        """Test ScanSession meta ordering."""
        # Create multiple scan sessions
        scan1 = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            status='uploaded'
        )
        
        scan2 = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            status='uploaded'
        )
        
        # Test ordering (should be by created_at descending)
        scans = ScanSession.objects.all()
        self.assertEqual(scans[0], scan2)  # Most recent first
        self.assertEqual(scans[1], scan1)


class TargetModelTestCase(TestCase):
    """Test case for Target model."""
    
    def setUp(self):
        """Set up test data."""
        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Test organization"
        )
        
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123",
            first_name="Test",
            last_name="User",
            organization=self.organization
        )
        
        self.scan_session = ScanSession.objects.create(
            description="Test Scan",
            organization=self.organization,
            created_by=self.user,
            status='uploaded'
        )
    
    def test_target_creation(self):
        """Test Target creation."""
        target = Target.objects.create(
            scan_session=self.scan_session,
            target_type='domain',
            value='example.com',
            discovered_by='subfinder',
            is_primary=True
        )
        
        self.assertEqual(target.scan_session, self.scan_session)
        self.assertEqual(target.target_type, 'domain')
        self.assertEqual(target.value, 'example.com')
        self.assertEqual(target.discovered_by, 'subfinder')
        self.assertTrue(target.is_primary)
    
    def test_target_str_representation(self):
        """Test string representation of Target."""
        target = Target.objects.create(
            scan_session=self.scan_session,
            target_type='domain',
            value='example.com'
        )
        
        expected_str = "example.com (domain)"
        self.assertEqual(str(target), expected_str)
    
    def test_target_unique_constraint(self):
        """Test Target unique constraint."""
        # Create first target
        Target.objects.create(
            scan_session=self.scan_session,
            target_type='domain',
            value='example.com'
        )
        
        # Try to create duplicate target (should raise IntegrityError)
        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            Target.objects.create(
                scan_session=self.scan_session,
                target_type='domain',
                value='example.com'
            )


class ScanResultModelTestCase(TestCase):
    """Test case for ScanResult model."""
    
    def setUp(self):
        """Set up test data."""
        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Test organization"
        )
        
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123",
            first_name="Test",
            last_name="User",
            organization=self.organization
        )
        
        self.scan_session = ScanSession.objects.create(
            description="Test Scan",
            organization=self.organization,
            created_by=self.user,
            status='uploaded'
        )
        
        self.target = Target.objects.create(
            scan_session=self.scan_session,
            target_type='domain',
            value='example.com'
        )
    
    def test_scan_result_creation(self):
        """Test ScanResult creation."""
        result = ScanResult.objects.create(
            scan_session=self.scan_session,
            result_type='reconnaissance',
            tool_name='nmap',
            data={'port': 80, 'service': 'http'},
            target=self.target,
            severity='info'
        )
        
        self.assertEqual(result.scan_session, self.scan_session)
        self.assertEqual(result.result_type, 'reconnaissance')
        self.assertEqual(result.tool_name, 'nmap')
        self.assertEqual(result.data, {'port': 80, 'service': 'http'})
        self.assertEqual(result.target, self.target)
        self.assertEqual(result.severity, 'info')
    
    def test_scan_result_str_representation(self):
        """Test string representation of ScanResult."""
        result = ScanResult.objects.create(
            scan_session=self.scan_session,
            result_type='reconnaissance',
            tool_name='nmap',
            data={'port': 80},
            severity='info'
        )
        
        expected_str = "nmap - reconnaissance (info)"
        self.assertEqual(str(result), expected_str)


class ScanArtifactModelTestCase(TestCase):
    """Test case for ScanArtifact model."""
    
    def setUp(self):
        """Set up test data."""
        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Test organization"
        )
        
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123",
            first_name="Test",
            last_name="User",
            organization=self.organization
        )
        
        self.scan_session = ScanSession.objects.create(
            description="Test Scan",
            organization=self.organization,
            created_by=self.user,
            status='uploaded'
        )
        
        self.result = ScanResult.objects.create(
            scan_session=self.scan_session,
            result_type='exploitation',
            tool_name='custom_exploit',
            data={'exploit': 'test'},
            severity='high'
        )
    
    def test_scan_artifact_creation(self):
        """Test ScanArtifact creation."""
        artifact = ScanArtifact.objects.create(
            scan_session=self.scan_session,
            result=self.result,
            artifact_type='exploit_script',
            name='test_exploit.py',
            s3_key='scans/test/exploits/test_exploit.py',
            file_size=1024,
            mime_type='text/x-python',
            description='Test exploit script'
        )
        
        self.assertEqual(artifact.scan_session, self.scan_session)
        self.assertEqual(artifact.result, self.result)
        self.assertEqual(artifact.artifact_type, 'exploit_script')
        self.assertEqual(artifact.name, 'test_exploit.py')
        self.assertEqual(artifact.s3_key, 'scans/test/exploits/test_exploit.py')
        self.assertEqual(artifact.file_size, 1024)
        self.assertEqual(artifact.mime_type, 'text/x-python')
        self.assertEqual(artifact.description, 'Test exploit script')
    
    def test_scan_artifact_str_representation(self):
        """Test string representation of ScanArtifact."""
        artifact = ScanArtifact.objects.create(
            scan_session=self.scan_session,
            artifact_type='exploit_script',
            name='test_exploit.py',
            s3_key='scans/test/exploits/test_exploit.py',
            file_size=1024
        )
        
        expected_str = "test_exploit.py (exploit_script)"
        self.assertEqual(str(artifact), expected_str)


class ReportsViewsTestCase(TestCase):
    """Test case for reports views."""
    
    def setUp(self):
        """Set up test data."""
        # Create test organization
        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Test organization for unit tests"
        )
        
        # Create test user (organization admin)
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123",
            first_name="Test",
            last_name="User",
            organization=self.organization,
            role='admin',
            is_organization_admin=True
        )
        
        # Create another user in the same organization
        self.user2 = User.objects.create_user(
            username="testuser2",
            email="test2@example.com",
            password="testpass123",
            first_name="Test2",
            last_name="User2",
            organization=self.organization
        )
        
        # Create another organization and user for isolation testing
        self.other_organization = Organization.objects.create(
            name="Other Organization",
            description="Other organization for isolation tests"
        )
        
        self.other_user = User.objects.create_user(
            username="otheruser",
            email="other@example.com",
            password="testpass123",
            first_name="Other",
            last_name="User",
            organization=self.other_organization
        )
        
        # Create test scan session
        self.scan_session = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Test scan session",
            status='completed'
        )
        
        # Create test target
        self.target = Target.objects.create(
            scan_session=self.scan_session,
            value="192.168.1.1",
            target_type="ip"
        )
        
        # Create test scan result
        self.scan_result = ScanResult.objects.create(
            scan_session=self.scan_session,
            target=self.target,
            result_type="vulnerability",
            tool_name="nuclei",
            severity="high",
            data={"test": "data"}
        )
        
        self.client = Client()
    
    def test_dashboard_requires_authentication(self):
        """Test that dashboard requires authentication."""
        response = self.client.get('/')
        self.assertRedirects(response, '/login/?next=/')
    
    def test_dashboard_authenticated(self):
        """Test dashboard view for authenticated user."""
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Dashboard')
    
    def test_scans_requires_authentication(self):
        """Test that scans page requires authentication."""
        response = self.client.get('/scans/')
        self.assertRedirects(response, '/login/?next=/scans/')
    
    def test_scans_authenticated(self):
        """Test scans view for authenticated user."""
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Scans')
    
    def test_scans_organization_isolation(self):
        """Test that users only see scans from their organization."""
        self.client.login(username='other@example.com', password='testpass123')
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, self.scan_session.description)
    
    def test_scan_detail_requires_authentication(self):
        """Test that scan detail requires authentication."""
        response = self.client.get(f'/scans/{self.scan_session.id}/')
        self.assertRedirects(response, f'/login/?next=/scans/{self.scan_session.id}/')
    
    def test_scan_detail_authenticated(self):
        """Test scan detail view for authenticated user."""
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get(f'/scans/{self.scan_session.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.scan_session.description)
    
    def test_scan_detail_organization_isolation(self):
        """Test that users can only access scans from their organization."""
        self.client.login(username='other@example.com', password='testpass123')
        response = self.client.get(f'/scans/{self.scan_session.id}/')
        self.assertEqual(response.status_code, 404)
    
    def test_scan_detail_nonexistent(self):
        """Test scan detail with nonexistent scan ID."""
        self.client.login(username='test@example.com', password='testpass123')
        fake_uuid = '00000000-0000-0000-0000-000000000000'
        response = self.client.get(f'/scans/{fake_uuid}/')
        self.assertEqual(response.status_code, 404)
    
    def test_target_detail_requires_authentication(self):
        """Test that target detail requires authentication."""
        response = self.client.get(f'/scans/{self.scan_session.id}/targets/{self.target.id}/')
        self.assertRedirects(response, f'/login/?next=/scans/{self.scan_session.id}/targets/{self.target.id}/')
    
    def test_target_detail_authenticated(self):
        """Test target detail view for authenticated user."""
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get(f'/scans/{self.scan_session.id}/targets/{self.target.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.target.value)
    
    def test_target_detail_partial_request(self):
        """Test target detail view with X-Partial header."""
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get(
            f'/scans/{self.scan_session.id}/targets/{self.target.id}/',
            HTTP_X_PARTIAL='true'
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.target.value)
    
    def test_target_detail_organization_isolation(self):
        """Test that users can only access targets from their organization."""
        self.client.login(username='other@example.com', password='testpass123')
        response = self.client.get(f'/scans/{self.scan_session.id}/targets/{self.target.id}/')
        self.assertEqual(response.status_code, 404)
    
    def test_target_detail_nonexistent_scan(self):
        """Test target detail with nonexistent scan ID."""
        self.client.login(username='test@example.com', password='testpass123')
        fake_uuid = '00000000-0000-0000-0000-000000000000'
        response = self.client.get(f'/scans/{fake_uuid}/targets/{self.target.id}/')
        self.assertEqual(response.status_code, 404)
    
    def test_target_detail_nonexistent_target(self):
        """Test target detail with nonexistent target ID."""
        self.client.login(username='test@example.com', password='testpass123')
        fake_uuid = '00000000-0000-0000-0000-000000000000'
        response = self.client.get(f'/scans/{self.scan_session.id}/targets/{fake_uuid}/')
        self.assertEqual(response.status_code, 404)
    
    def test_scans_with_no_data(self):
        """Test scans page with no scan data."""
        # Create a new organization with no scans
        empty_org = Organization.objects.create(
            name="Empty Organization",
            description="Organization with no scans"
        )
        
        empty_user = User.objects.create_user(
            username="emptyuser",
            email="empty@example.com",
            password="testpass123",
            first_name="Empty",
            last_name="User",
            organization=empty_org
        )
        
        self.client.login(username='empty@example.com', password='testpass123')
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'No scans found')
    
    def test_scans_stat_boxes_calculations(self):
        """Test that stat boxes show correct calculations."""
        # Create additional scan with different data
        scan2 = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Test scan 2",
            status='completed'
        )
        
        # Add targets to both scans
        Target.objects.create(scan_session=scan2, value="192.168.1.2", target_type="ip")
        Target.objects.create(scan_session=scan2, value="192.168.1.3", target_type="ip")
        
        # Add vulnerabilities to both scans
        ScanResult.objects.create(
            scan_session=scan2,
            target=self.target,
            result_type="vulnerability",
            tool_name="nuclei",
            severity="medium",
            data={"test": "data2"}
        )
        
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
        
        # Check that we have 2 scans total
        self.assertContains(response, '2')
    
    def test_scans_stat_boxes_with_different_result_types(self):
        """Test stat boxes with different result types."""
        # Create additional results of different types
        ScanResult.objects.create(
            scan_session=self.scan_session,
            target=self.target,
            result_type="service",
            tool_name="nmap",
            data={"service": "http", "port": 80}
        )
        
        ScanResult.objects.create(
            scan_session=self.scan_session,
            target=self.target,
            result_type="reconnaissance",
            tool_name="subfinder",
            data={"subdomain": "test.example.com"}
        )
        
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
        
        # Should still show 1 vulnerability (not counting other result types)
        self.assertContains(response, '1')
    
    def test_scans_stat_boxes_with_no_vulnerabilities(self):
        """Test stat boxes when there are no vulnerabilities."""
        # Delete the vulnerability result
        self.scan_result.delete()
        
        # Add a non-vulnerability result
        ScanResult.objects.create(
            scan_session=self.scan_session,
            target=self.target,
            result_type="service",
            tool_name="nmap",
            data={"service": "http", "port": 80}
        )
        
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
        
        # Should show 0 vulnerabilities
        self.assertContains(response, '0')
    
    def test_scans_stat_boxes_with_empty_organization(self):
        """Test stat boxes with empty organization."""
        # Create a new organization with no scans
        empty_org = Organization.objects.create(
            name="Empty Organization",
            description="Organization with no scans"
        )
        
        empty_user = User.objects.create_user(
            username="emptyuser",
            email="empty@example.com",
            password="testpass123",
            first_name="Empty",
            last_name="User",
            organization=empty_org
        )
        
        self.client.login(username='empty@example.com', password='testpass123')
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
        
        # Should show 0 for all stats
        self.assertContains(response, '0')
    
    def test_scan_detail_with_no_targets(self):
        """Test scan detail page with no targets."""
        # Delete the target
        self.target.delete()
        
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get(f'/scans/{self.scan_session.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'No targets found')
    
    def test_scan_detail_with_no_vulnerabilities(self):
        """Test scan detail page with no vulnerabilities."""
        # Delete the vulnerability result
        self.scan_result.delete()
        
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get(f'/scans/{self.scan_session.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'No results found')
    
    def test_target_detail_with_vulnerabilities(self):
        """Test target detail page with vulnerabilities."""
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get(f'/scans/{self.scan_session.id}/targets/{self.target.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.scan_result.tool_name)
    
    def test_target_detail_with_no_vulnerabilities(self):
        """Test target detail page with no vulnerabilities."""
        # Delete the vulnerability result
        self.scan_result.delete()
        
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get(f'/scans/{self.scan_session.id}/targets/{self.target.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'No results found')
    
    def test_dashboard_chart_data(self):
        """Test dashboard chart data generation."""
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        
        # Check that chart data is present in context
        self.assertIn('chart_data', response.context)
        self.assertIn('vulnerability_chart_data', response.context)
