"""
Tests for reports models.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.files.storage import default_storage

from organizations.models import Organization
from reports.models import ScanSession, Target, ScanResult, ScanArtifact

from .test_base import ReportsTestCase

User = get_user_model()


class ScanSessionModelTestCase(ReportsTestCase):
    """Test case for ScanSession model."""
    
    def test_scan_session_creation(self):
        """Test creating a scan session."""
        scan_session = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Test scan session",
            status='completed'
        )
        
        self.assertEqual(scan_session.organization, self.organization)
        self.assertEqual(scan_session.created_by, self.user)
        self.assertEqual(scan_session.description, "Test scan session")
        self.assertEqual(scan_session.status, 'completed')
        self.assertIsNotNone(scan_session.created_at)
        # ScanSession doesn't have updated_at field
    
    def test_scan_session_str_representation(self):
        """Test string representation of scan session."""
        scan_session = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Test scan session",
            status='completed'
        )
        
        expected_str = f"Session {scan_session.id} (completed)"
        self.assertEqual(str(scan_session), expected_str)
    
    def test_scan_session_meta_ordering(self):
        """Test that scan sessions are ordered by created_at descending."""
        # Create multiple scan sessions
        scan1 = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="First scan",
            status='completed'
        )
        
        scan2 = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Second scan",
            status='completed'
        )
        
        # Get all scan sessions
        scans = ScanSession.objects.all()
        
        # Should be ordered by created_at descending (newest first)
        self.assertEqual(scans[0], scan2)
        self.assertEqual(scans[1], scan1)


class TargetModelTestCase(ReportsTestCase):
    """Test case for Target model."""
    
    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.scan_session = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Test scan session",
            status='completed'
        )
    
    def test_target_creation(self):
        """Test creating a target."""
        target = Target.objects.create(
            scan_session=self.scan_session,
            value="192.168.1.1",
            target_type="ip"
        )
        
        self.assertEqual(target.scan_session, self.scan_session)
        self.assertEqual(target.value, "192.168.1.1")
        self.assertEqual(target.target_type, "ip")
        self.assertIsNotNone(target.created_at)
    
    def test_target_str_representation(self):
        """Test string representation of target."""
        target = Target.objects.create(
            scan_session=self.scan_session,
            value="192.168.1.1",
            target_type="ip"
        )
        
        expected_str = "192.168.1.1 (ip)"
        self.assertEqual(str(target), expected_str)
    
    def test_target_unique_constraint(self):
        """Test that targets have unique constraint on scan_session and value."""
        # Create first target
        Target.objects.create(
            scan_session=self.scan_session,
            value="192.168.1.1",
            target_type="ip"
        )
        
        # Try to create duplicate target
        with self.assertRaises(Exception):  # IntegrityError
            Target.objects.create(
                scan_session=self.scan_session,
                value="192.168.1.1",
                target_type="ip"
            )


class ScanResultModelTestCase(ReportsTestCase):
    """Test case for ScanResult model."""
    
    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.scan_session = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Test scan session",
            status='completed'
        )
        self.target = Target.objects.create(
            scan_session=self.scan_session,
            value="192.168.1.1",
            target_type="ip"
        )
    
    def test_scan_result_creation(self):
        """Test creating a scan result."""
        scan_result = ScanResult.objects.create(
            scan_session=self.scan_session,
            target=self.target,
            result_type="vulnerability",
            tool_name="nuclei",
            severity="high",
            data={"test": "data"}
        )
        
        self.assertEqual(scan_result.scan_session, self.scan_session)
        self.assertEqual(scan_result.target, self.target)
        self.assertEqual(scan_result.result_type, "vulnerability")
        self.assertEqual(scan_result.tool_name, "nuclei")
        self.assertEqual(scan_result.severity, "high")
        self.assertEqual(scan_result.data, {"test": "data"})
        self.assertIsNotNone(scan_result.created_at)
    
    def test_scan_result_str_representation(self):
        """Test string representation of scan result."""
        scan_result = ScanResult.objects.create(
            scan_session=self.scan_session,
            target=self.target,
            result_type="vulnerability",
            tool_name="nuclei",
            severity="high",
            data={"test": "data"}
        )
        
        expected_str = "nuclei - vulnerability (high)"
        self.assertEqual(str(scan_result), expected_str)


class ScanArtifactModelTestCase(ReportsTestCase):
    """Test case for ScanArtifact model."""
    
    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.scan_session = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Test scan session",
            status='completed'
        )
    
    def test_scan_artifact_creation(self):
        """Test creating a scan artifact."""
        artifact = ScanArtifact.objects.create(
            scan_session=self.scan_session,
            artifact_type="log_file",
            name="test.log",
            s3_key="test.log",
            file_size=1024,
            metadata={"test": "data"}
        )
        
        self.assertEqual(artifact.scan_session, self.scan_session)
        self.assertEqual(artifact.artifact_type, "log_file")
        self.assertEqual(artifact.name, "test.log")
        self.assertEqual(artifact.s3_key, "test.log")
        self.assertEqual(artifact.file_size, 1024)
        self.assertEqual(artifact.metadata, {"test": "data"})
        self.assertIsNotNone(artifact.created_at)
    
    def test_scan_artifact_str_representation(self):
        """Test string representation of scan artifact."""
        artifact = ScanArtifact.objects.create(
            scan_session=self.scan_session,
            artifact_type="log_file",
            name="test.log",
            s3_key="test.log",
            file_size=1024,
            metadata={"test": "data"}
        )
        
        expected_str = "test.log (log_file)"
        self.assertEqual(str(artifact), expected_str)
