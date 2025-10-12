"""
Tests for target management functionality.
"""

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from reports.models import ScanSession, Target, ScanResult

from .test_base import AccountsTestCase

User = get_user_model()


class TargetManagementTestCase(AccountsTestCase):
    """Test case for target management views."""
    
    def setUp(self):
        """Set up additional test data for target management tests."""
        super().setUp()
        
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
    
    def test_update_targets_requires_authentication(self):
        """Test that update targets requires authentication."""
        response = self.client.get('/accounts/update-targets/')
        self.assertRedirects(response, '/accounts/login/?next=/accounts/update-targets/')
    
    def test_update_targets_get_request(self):
        """Test GET request to update targets page."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/accounts/update-targets/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Set Up Your Targets')
        self.assertContains(response, 'Enter targets separated by commas')
    
    def test_update_targets_post_valid(self):
        """Test POST request with valid target data."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.post('/accounts/update-targets/', {
            'targets': 'example.com, 192.168.1.1, https://app.example.com',
            'consent_checkbox': 'on'
        })
        
        # Should redirect after successful update
        self.assertRedirects(response, '/')
    
    def test_update_targets_ajax_request(self):
        """Test AJAX request to update targets."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.post('/accounts/update-targets/', {
            'targets': 'example.com, 192.168.1.1',
            'consent_checkbox': 'on'
        }, HTTP_X_PARTIAL='true')
        
        self.assertEqual(response.status_code, 200)
        # Should return JSON response
        import json
        data = json.loads(response.content)
        self.assertTrue(data['success'])
        self.assertEqual(data['message'], 'Targets updated successfully!')
