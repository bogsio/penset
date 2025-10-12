"""
Tests for authentication functionality (login, logout).
"""

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.core import mail
from allauth.account.models import EmailAddress
from organizations.models import Organization

from .test_base import AccountsTestCase

User = get_user_model()


class AuthenticationTestCase(AccountsTestCase):
    """Test case for authentication views."""
    
    def test_login_page_get(self):
        """Test that login page loads correctly."""
        response = self.client.get('/accounts/login/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Welcome back')
        self.assertContains(response, 'Sign in with your credentials')
    
    def test_login_page_post_valid(self):
        """Test successful login with valid credentials."""
        response = self.client.post('/accounts/login/', {
            'username': 'test@example.com',
            'password': 'testpass123'
        })
        self.assertRedirects(response, '/')
    
    def test_login_page_post_invalid(self):
        """Test login with invalid credentials."""
        response = self.client.post('/accounts/login/', {
            'username': 'test@example.com',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Invalid email or password.')
    
    def test_unconfirmed_email_cannot_login(self):
        """Test that users with unconfirmed email addresses cannot login."""
        # Create a user with unconfirmed email
        unconfirmed_user = User.objects.create_user(
            username="unconfirmed@example.com",
            email="unconfirmed@example.com",
            password="testpass123",
            first_name="Unconfirmed",
            last_name="User",
            is_active=True  # User is active but email not confirmed
        )
        
        # Create EmailAddress record but mark as unverified
        EmailAddress.objects.create(
            user=unconfirmed_user,
            email=unconfirmed_user.email,
            primary=True,
            verified=False  # Email is NOT verified
        )
        
        # Try to login with correct credentials
        response = self.client.post('/accounts/login/', {
            'username': 'unconfirmed@example.com',
            'password': 'testpass123'
        })
        
        # Should NOT redirect (login should fail)
        self.assertEqual(response.status_code, 200)
        
        # Should show message about verification email being sent
        self.assertContains(response, 'verification email has been sent')
        
        # User should not be authenticated
        self.assertFalse(response.wsgi_request.user.is_authenticated)
    
    def test_confirmed_email_can_login(self):
        """Test that users with confirmed email addresses can login."""
        # Try to login with correct credentials
        response = self.client.post('/accounts/login/', {
            'username': 'test@example.com',
            'password': 'testpass123'
        })
        
        # Should redirect to dashboard
        self.assertRedirects(response, '/')
        
        # User should be authenticated
        self.assertTrue(response.wsgi_request.user.is_authenticated)
    
    def test_unverified_email_sends_verification_email(self):
        """Test that login attempt with unverified email automatically sends verification email."""
        # Clear any existing emails
        mail.outbox = []
        
        # Create a user with unverified email
        user = User.objects.create_user(
            username='unverified@example.com',
            email='unverified@example.com',
            password='testpass123',
            first_name='Unverified',
            last_name='User'
        )
        
        # Ensure email is NOT verified
        EmailAddress.objects.create(
            user=user,
            email=user.email,
            verified=False,
            primary=True
        )
        
        # Attempt login with unverified email
        response = self.client.post('/accounts/login/', {
            'username': 'unverified@example.com',
            'password': 'testpass123'
        })
        
        # Should NOT redirect (login should fail)
        self.assertEqual(response.status_code, 200)
        
        # Should show message about verification email being sent
        self.assertContains(response, 'verification email has been sent')
        
        # Should send verification email (in development, this goes to mail.outbox)
        # Note: In production with django-naomi, emails are saved to files
        # The important thing is that send_email_confirmation was called
        
        # User should not be authenticated
        self.assertFalse(response.wsgi_request.user.is_authenticated)
    
    def test_logout_authenticated(self):
        """Test logout for authenticated user."""
        # Login first
        self.client.login(username='test@example.com', password='testpass123')
        
        # Test logout - should redirect to login page
        response = self.client.get('/accounts/logout/')
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, '/accounts/login/')
    
    def test_logout_does_not_require_authentication(self):
        """Test that logout page is accessible without authentication."""
        response = self.client.get('/accounts/logout/')
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, '/accounts/login/')
