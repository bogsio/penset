"""
Base test classes and utilities for reports tests.
"""

import os
import tempfile
import zipfile
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.core.files import File
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile

from organizations.models import Organization
from reports.models import ScanSession, Target, ScanResult, ScanArtifact

User = get_user_model()


class ReportsTestCase(TestCase):
    """Base test case for reports tests with common setup."""
    
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
                zipf.writestr('summary_report.txt', 'Test summary report')
                zipf.writestr('enriched_summary_report.json', '{"test": "data"}')
                zipf.writestr('exploitation_summary_report.json', '{"test": "data"}')
                zipf.writestr('vulnerability_summary_report.json', '{"test": "data"}')
                
                # Add result files
                zipf.writestr('recon_results.json', '{"test": "data"}')
                zipf.writestr('enum_results.json', '{"test": "data"}')
                zipf.writestr('vuln_results.json', '{"test": "data"}')
                zipf.writestr('exploit_results.json', '{"test": "data"}')
                zipf.writestr('enriched_results.json', '{"test": "data"}')
                
                # Add log files
                zipf.writestr('recon.log', 'Test recon log')
                zipf.writestr('enum.log', 'Test enum log')
                zipf.writestr('vuln.log', 'Test vuln log')
                zipf.writestr('exploit.log', 'Test exploit log')
                
                # Add target files
                zipf.writestr('domains/domains.txt', 'example.com\ntest.com')
                zipf.writestr('ips/ips.txt', '192.168.1.1\n10.0.0.1')
                zipf.writestr('emails/emails.txt', 'test@example.com\nadmin@test.com')
                
                # Add service files
                zipf.writestr('ports/ports.json', '{"test": "data"}')
                zipf.writestr('services/services.json', '{"test": "data"}')
                zipf.writestr('web/web.json', '{"test": "data"}')
                
                # Add vulnerability files
                zipf.writestr('vulnerabilities/vulnerabilities.json', '{"test": "data"}')
                
                # Add exploit files
                zipf.writestr('exploits/exploit1.py', 'print("test exploit")')
                zipf.writestr('exploit_results/exploit1.json', '{"test": "data"}')
                
                # Add raw output files
                zipf.writestr('raw_output/raw1.txt', 'Raw output data')
                zipf.writestr('raw_output/raw2.json', '{"raw": "data"}')
        
        return tmp_file.name
    
    def tearDown(self):
        """Clean up test data."""
        # Clean up the temporary ZIP file
        if hasattr(self, 'toy_zip_path') and os.path.exists(self.toy_zip_path):
            os.unlink(self.toy_zip_path)
        
        # Clean up any uploaded files
        if hasattr(self, 'scan_session') and self.scan_session.archive_file:
            if default_storage.exists(self.scan_session.archive_file.name):
                default_storage.delete(self.scan_session.archive_file.name)
