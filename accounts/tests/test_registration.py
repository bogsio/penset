"""
Tests for user registration functionality.
"""

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from allauth.account.models import EmailAddress
from organizations.models import Organization

from .test_base import AccountsTestCase

User = get_user_model()


class RegistrationTestCase(AccountsTestCase):
    """Test case for registration views."""
    
    def test_register_page_get(self):
        """Test that registration page loads correctly."""
        response = self.client.get('/accounts/register/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Create Account')
        self.assertContains(response, 'Step 1: Enter your personal details')
    
    def test_register_page_post_valid(self):
        """Test successful user registration."""
        response = self.client.post('/accounts/register/', {
            'first_name': 'New',
            'last_name': 'User',
            'email': 'newuser@example.com',
            'password1': 'testpass123',
            'password2': 'testpass123'
        })
        
        # Should redirect to verification sent page
        self.assertRedirects(response, '/accounts/verification-sent/newuser@example.com/')
        
        # Check that user was created but is inactive
        user = User.objects.get(email='newuser@example.com')
        self.assertEqual(user.first_name, 'New')
        self.assertEqual(user.last_name, 'User')
        self.assertFalse(user.is_active)  # User should be inactive until email verification
        
        # Check that EmailAddress record was created
        email_address = EmailAddress.objects.get(email='newuser@example.com')
        self.assertFalse(email_address.verified)  # Email should not be verified yet
    
    def test_register_page_post_duplicate_email(self):
        """Test registration with duplicate email address."""
        response = self.client.post('/accounts/register/', {
            'first_name': 'Duplicate',
            'last_name': 'User',
            'email': 'test@example.com',  # This email already exists
            'password1': 'testpass123',
            'password2': 'testpass123'
        })
        
        # Should show error message
        self.assertEqual(response.status_code, 200)
        # Check for the error message in the response content
        self.assertContains(response, 'A user with this email address already exists')
    
    def test_register_page_post_invalid(self):
        """Test registration with invalid data."""
        response = self.client.post('/accounts/register/', {
            'first_name': '',  # Empty first name
            'last_name': 'User',
            'email': 'invalid-email',  # Invalid email
            'password1': 'short',  # Too short password
            'password2': 'different'  # Passwords don't match
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Please correct the errors below.')
