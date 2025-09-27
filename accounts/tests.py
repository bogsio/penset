"""
Tests for the accounts app views and functionality.
"""

import uuid
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile

from organizations.models import Organization
from reports.models import ScanSession, Target, ScanResult

User = get_user_model()


class AccountsViewsTestCase(TestCase):
    """Test case for accounts views."""
    
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
    
    def test_login_page_get(self):
        """Test login page GET request."""
        response = self.client.get('/accounts/login/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Login')
    
    def test_login_page_post_valid(self):
        """Test login page POST with valid credentials."""
        response = self.client.post('/accounts/login/', {
            'username': 'test@example.com',
            'password': 'testpass123'
        })
        self.assertRedirects(response, '/')
    
    def test_login_page_post_invalid(self):
        """Test login page POST with invalid credentials."""
        response = self.client.post('/accounts/login/', {
            'username': 'test@example.com',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Invalid email or password')
    
    def test_register_page_get(self):
        """Test register page GET request."""
        response = self.client.get('/accounts/register/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Register')
    
    def test_register_page_post_valid(self):
        """Test register page POST with valid data."""
        response = self.client.post('/accounts/register/', {
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password1': 'newpass123',
            'password2': 'newpass123'
        })
        self.assertRedirects(response, '/accounts/register/organization/')
        
        # Check that registration data is stored in session
        self.assertIn('registration_data', self.client.session)
    
    def test_register_page_post_invalid(self):
        """Test register page POST with invalid data."""
        response = self.client.post('/accounts/register/', {
            'email': 'invalid-email',
            'first_name': '',
            'last_name': '',
            'password1': 'short',
            'password2': 'different'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Please correct the errors below')
    
    def test_register_organization_page_requires_session(self):
        """Test that organization registration requires session data."""
        response = self.client.get('/accounts/register/organization/')
        self.assertRedirects(response, '/accounts/register/')
    
    def test_register_organization_page_with_session(self):
        """Test organization registration page with session data."""
        # Set up session data
        session = self.client.session
        session['registration_data'] = {
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': 'newpass123'
        }
        session.save()
        
        response = self.client.get('/accounts/register/organization/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Organization Details')
    
    def test_register_organization_post_valid(self):
        """Test organization registration POST with valid data."""
        # Set up session data
        session = self.client.session
        session['registration_data'] = {
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': 'newpass123'
        }
        session.save()
        
        response = self.client.post('/accounts/register/organization/', {
            'name': 'New Organization',
            'description': 'A new test organization',
            'website': 'https://example.com',
            'contact_email': 'contact@example.com'
        })
        
        self.assertRedirects(response, '/')
        
        # Check that user and organization were created
        self.assertTrue(User.objects.filter(email='newuser@example.com').exists())
        self.assertTrue(Organization.objects.filter(name='New Organization').exists())
        
        # Check that session data was cleared
        self.assertNotIn('registration_data', self.client.session)
    
    def test_logout_does_not_require_authentication(self):
        """Test that logout view doesn't require authentication."""
        response = self.client.get('/accounts/logout/')
        self.assertRedirects(response, '/accounts/login/')
    
    def test_logout_authenticated(self):
        """Test logout view for authenticated user."""
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get('/accounts/logout/')
        self.assertRedirects(response, '/accounts/login/')
    
    def test_settings_page_requires_authentication(self):
        """Test that settings page requires authentication."""
        response = self.client.get('/accounts/settings/')
        self.assertRedirects(response, '/accounts/login/?next=/accounts/settings/')
    
    def test_settings_page_requires_organization_admin(self):
        """Test that settings page requires organization admin role."""
        # Login as non-admin user
        self.client.login(username='test2@example.com', password='testpass123')
        response = self.client.get('/accounts/settings/')
        self.assertRedirects(response, '/')
    
    def test_settings_page_authenticated_admin(self):
        """Test settings page for authenticated admin user."""
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get('/accounts/settings/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Organization Settings')
    
    def test_settings_page_post_valid(self):
        """Test settings page POST with valid data."""
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.post('/accounts/settings/', {
            'name': 'Updated Organization',
            'description': 'Updated description',
            'website': 'https://updated.com',
            'contact_email': 'updated@example.com',
            'targets': '192.168.1.0/24'
        })
        self.assertRedirects(response, '/accounts/settings/')
        
        # Check that organization was updated
        self.organization.refresh_from_db()
        self.assertEqual(self.organization.name, 'Updated Organization')
        self.assertEqual(self.organization.targets, '192.168.1.0/24')
    
    def test_settings_page_displays_correct_scan_count(self):
        """Test that settings page displays correct scan count."""
        # Create additional scan
        ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Another test scan",
            status='completed'
        )
        
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get('/accounts/settings/')
        self.assertEqual(response.status_code, 200)
        
        # Should show 2 scans
        self.assertContains(response, '2')
    
    def test_settings_page_displays_correct_user_count(self):
        """Test that settings page displays correct user count."""
        # Create additional user
        User.objects.create_user(
            username="testuser3",
            email="test3@example.com",
            password="testpass123",
            first_name="Test3",
            last_name="User3",
            organization=self.organization
        )
        
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get('/accounts/settings/')
        self.assertEqual(response.status_code, 200)
        
        # Should show 3 users
        self.assertContains(response, '3')
    
    def test_update_targets_requires_authentication(self):
        """Test that update targets requires authentication."""
        response = self.client.post('/accounts/update-targets/', {
            'targets': '192.168.1.0/24'
        })
        self.assertRedirects(response, '/accounts/login/?next=/accounts/update-targets/')
    
    def test_update_targets_post_valid(self):
        """Test update targets POST with valid data."""
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.post('/accounts/update-targets/', {
            'targets': '192.168.1.0/24, 10.0.0.0/8'
        })
        
        # Should redirect back to referring page or dashboard
        self.assertEqual(response.status_code, 302)
        
        # Check that targets were updated
        self.organization.refresh_from_db()
        self.assertEqual(self.organization.targets, '192.168.1.0/24, 10.0.0.0/8')
    
    def test_update_targets_ajax_request(self):
        """Test update targets with AJAX request."""
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.post('/accounts/update-targets/', {
            'targets': '192.168.1.0/24'
        }, HTTP_X_PARTIAL='true')
        
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(response.content, {
            'success': True,
            'message': 'Targets updated successfully!'
        })
    
    def test_update_targets_get_request(self):
        """Test update targets GET request returns form."""
        self.client.login(username='test@example.com', password='testpass123')
        response = self.client.get('/accounts/update-targets/', HTTP_X_PARTIAL='true')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'targets')