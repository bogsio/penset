"""
Tests for user settings functionality.
"""

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from reports.models import ScanSession, Target, ScanResult

from .test_base import AccountsTestCase

User = get_user_model()


class SettingsTestCase(AccountsTestCase):
    """Test case for settings views."""
    
    def setUp(self):
        """Set up additional test data for settings tests."""
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
    
    def test_settings_page_requires_authentication(self):
        """Test that settings page requires authentication."""
        response = self.client.get('/accounts/settings/')
        self.assertRedirects(response, '/accounts/login/?next=/accounts/settings/')
    
    def test_settings_page_requires_organization_admin(self):
        """Test that settings page requires organization admin role."""
        # Login as non-admin user
        self.client.login(username='test2@example.com', password='testpass123')
        
        response = self.client.get('/accounts/settings/')
        # Should redirect to dashboard when user doesn't have permission
        self.assertRedirects(response, '/')
    
    def test_settings_page_authenticated_admin(self):
        """Test settings page for authenticated admin user."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/accounts/settings/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Settings')
        self.assertContains(response, 'Test User')
    
    def test_settings_page_displays_correct_user_count(self):
        """Test that settings page displays correct user count."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/accounts/settings/')
        self.assertEqual(response.status_code, 200)
        # Should show 2 users (testuser and testuser2)
        self.assertContains(response, '2')
    
    def test_settings_page_displays_correct_scan_count(self):
        """Test that settings page displays correct scan count."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/accounts/settings/')
        self.assertEqual(response.status_code, 200)
        # Should show 1 scan session
        self.assertContains(response, '1')
    
    def test_settings_page_post_valid(self):
        """Test settings page POST with valid data."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.post('/accounts/settings/', {
            'name': 'Updated Organization',
            'description': 'Updated description',
            'website': 'https://updated.example.com',
            'contact_email': 'updated@example.com',
            'targets': 'updated.com, 192.168.1.100'
        })
        
        # Should redirect after successful update
        self.assertRedirects(response, '/accounts/settings/')
        
        # Check that organization data was updated
        self.organization.refresh_from_db()
        self.assertEqual(self.organization.name, 'Updated Organization')
        self.assertEqual(self.organization.description, 'Updated description')
        self.assertEqual(self.organization.website, 'https://updated.example.com')
        self.assertEqual(self.organization.contact_email, 'updated@example.com')
        self.assertEqual(self.organization.targets, 'updated.com, 192.168.1.100')
