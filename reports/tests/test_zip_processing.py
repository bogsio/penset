"""
Tests for ZIP file processing functionality.
"""

import os
import tempfile
import zipfile
from django.test import TestCase, override_settings
from django.core.files import File
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile

from reports.models import ScanSession, Target, ScanResult, ScanArtifact
from reports.admin_forms import ScanSessionAdminForm, ScanUploadForm

from .test_base import ReportsTestCase


class ScanSessionZipProcessingTestCase(ReportsTestCase):
    """Test case for ZIP file processing functionality."""
    
    def test_scan_session_creation(self):
        """Test creating a scan session with ZIP file."""
        with open(self.toy_zip_path, 'rb') as f:
            uploaded_file = SimpleUploadedFile(
                "test_scan.zip",
                f.read(),
                content_type="application/zip"
            )
        
        scan_session = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Test scan session",
            status='completed',
            archive_file=uploaded_file
        )
        
        self.assertEqual(scan_session.organization, self.organization)
        self.assertEqual(scan_session.created_by, self.user)
        self.assertEqual(scan_session.description, "Test scan session")
        self.assertEqual(scan_session.status, 'completed')
        self.assertIsNotNone(scan_session.archive_file)
    
    def test_scan_session_filefield(self):
        """Test that scan session file field works correctly."""
        with open(self.toy_zip_path, 'rb') as f:
            uploaded_file = SimpleUploadedFile(
                "test_scan.zip",
                f.read(),
                content_type="application/zip"
            )
        
        scan_session = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Test scan session",
            status='completed',
            archive_file=uploaded_file
        )
        
        # Check that file was saved
        self.assertTrue(default_storage.exists(scan_session.archive_file.name))
        
        # Check file size
        self.assertGreater(scan_session.archive_file.size, 0)
    
    def test_scan_session_relationships(self):
        """Test relationships between scan session and related models."""
        with open(self.toy_zip_path, 'rb') as f:
            uploaded_file = SimpleUploadedFile(
                "test_scan.zip",
                f.read(),
                content_type="application/zip"
            )
        
        scan_session = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Test scan session",
            status='completed',
            archive_file=uploaded_file
        )
        
        # Create target
        target = Target.objects.create(
            scan_session=scan_session,
            value="192.168.1.1",
            target_type="ip"
        )
        
        # Create scan result
        scan_result = ScanResult.objects.create(
            scan_session=scan_session,
            target=target,
            result_type="vulnerability",
            tool_name="nuclei",
            severity="high",
            data={"test": "data"}
        )
        
        # Create scan artifact
        artifact = ScanArtifact.objects.create(
            scan_session=scan_session,
            artifact_type="log_file",
            name="test.log",
            s3_key="test.log",
            file_size=1024,
            metadata={"test": "data"}
        )
        
        # Test relationships
        self.assertEqual(target.scan_session, scan_session)
        self.assertEqual(scan_result.scan_session, scan_session)
        self.assertEqual(scan_result.target, target)
        self.assertEqual(artifact.scan_session, scan_session)
        
        # Test reverse relationships
        self.assertIn(target, scan_session.targets.all())
        self.assertIn(scan_result, scan_session.results.all())
        self.assertIn(artifact, scan_session.artifacts.all())
    
    def test_scan_session_status_workflow(self):
        """Test scan session status workflow."""
        scan_session = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Test scan session",
            status='pending'
        )
        
        # Test status transitions
        self.assertEqual(scan_session.status, 'pending')
        
        scan_session.status = 'running'
        scan_session.save()
        self.assertEqual(scan_session.status, 'running')
        
        scan_session.status = 'completed'
        scan_session.save()
        self.assertEqual(scan_session.status, 'completed')
    
    def test_scan_session_duration_calculation(self):
        """Test scan session duration calculation."""
        from datetime import datetime, timedelta
        
        scan_session = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Test scan session",
            status='completed',
            started_at=datetime.now() - timedelta(minutes=5),
            completed_at=datetime.now()
        )
        
        # Test duration calculation
        duration = scan_session.duration
        self.assertIsNotNone(duration)
        self.assertGreaterEqual(duration.total_seconds(), 0)
    
    def test_scan_session_metadata_tracking(self):
        """Test scan session metadata tracking."""
        scan_session = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Test scan session",
            status='completed'
        )
        
        # Test metadata fields
        self.assertIsNotNone(scan_session.created_at)
        # ScanSession doesn't have updated_at field
        
        # Test that description can be modified
        original_description = scan_session.description
        scan_session.description = "Updated description"
        scan_session.save()
        
        self.assertNotEqual(scan_session.description, original_description)
    
    def test_scan_upload_form_validation(self):
        """Test scan upload form validation."""
        form_data = {
            'name': 'Test Scan Upload',
            'description': 'Test scan upload',
            'status': 'pending'
        }
        
        with open(self.toy_zip_path, 'rb') as f:
            file_data = {
                'archive': SimpleUploadedFile(
                    "test_scan.zip",
                    f.read(),
                    content_type="application/zip"
                )
            }
        
        form = ScanUploadForm(form_data, file_data)
        if not form.is_valid():
            print(f"Form errors: {form.errors}")
        self.assertTrue(form.is_valid())
    
    def test_admin_form_zip_processing(self):
        """Test admin form ZIP processing."""
        form_data = {
            'organization': self.organization.id,
            'created_by': self.user.id,
            'description': 'Test admin scan',
            'status': 'completed'
        }
        
        with open(self.toy_zip_path, 'rb') as f:
            file_data = {
                'archive_file': SimpleUploadedFile(
                    "test_scan.zip",
                    f.read(),
                    content_type="application/zip"
                )
            }
        
        form = ScanSessionAdminForm(form_data, file_data)
        self.assertTrue(form.is_valid())
        
        scan_session = form.save()
        self.assertEqual(scan_session.description, 'Test admin scan')
        self.assertIsNotNone(scan_session.archive_file)
    
    def test_scan_session_admin_readonly_fields(self):
        """Test that admin form has correct readonly fields."""
        form = ScanSessionAdminForm()
        
        # Check that certain fields are readonly (if Meta.readonly_fields exists)
        if hasattr(form.Meta, 'readonly_fields'):
            readonly_fields = form.Meta.readonly_fields
            self.assertIn('created_at', readonly_fields)
