"""
Tests for organization setup functionality.
"""

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from organizations.models import Organization

from .test_base import AccountsTestCase

User = get_user_model()


class OrganizationSetupTestCase(AccountsTestCase):
    """Test case for organization setup views."""
    
    def test_register_organization_page_requires_session(self):
        """Test that organization setup page requires session data."""
        response = self.client.get('/accounts/register/organization/')
        self.assertRedirects(response, '/accounts/register/')
    
    def test_register_organization_page_with_session(self):
        """Test organization setup page with session data."""
        # Set up session data
        session = self.client.session
        session['registration_data'] = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        session.save()
        
        response = self.client.get('/accounts/register/organization/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Create Organization')
        self.assertContains(response, 'Set up your organization to get started')
    
    def test_register_organization_post_valid(self):
        """Test successful organization creation."""
        # Set up session data
        session = self.client.session
        session['registration_data'] = {
            'first_name': 'New',
            'last_name': 'User',
            'email': 'newuser@example.com',
            'password': 'testpass123'
        }
        session.save()
        
        response = self.client.post('/accounts/register/organization/', {
            'name': 'New Organization',
            'description': 'A new test organization',
            'website': 'https://neworg.example.com',
            'contact_email': 'contact@neworg.example.com'
        })
        
        # Should redirect to dashboard
        self.assertRedirects(response, '/')
        
        # Check that organization was created
        org = Organization.objects.get(name='New Organization')
        self.assertEqual(org.description, 'A new test organization')
        self.assertEqual(org.website, 'https://neworg.example.com')
        self.assertEqual(org.contact_email, 'contact@neworg.example.com')
        
        # Check that user was created and assigned to organization
        user = User.objects.get(email='newuser@example.com')
        self.assertEqual(user.organization, org)
        self.assertTrue(user.is_organization_admin)
        self.assertTrue(user.is_active)
    
    def test_register_organization_post_duplicate_email(self):
        """Test organization creation with duplicate email."""
        # Set up session data
        session = self.client.session
        session['registration_data'] = {
            'first_name': 'Duplicate',
            'last_name': 'User',
            'email': 'test@example.com',  # This email already exists
            'password': 'testpass123'
        }
        session.save()
        
        response = self.client.post('/accounts/register/organization/', {
            'name': 'Duplicate Organization',
            'description': 'A duplicate test organization',
            'website': 'https://duplicate.example.com',
            'contact_email': 'contact@duplicate.example.com'
        })
        
        # Should redirect to register page with error message
        self.assertRedirects(response, '/accounts/register/')
