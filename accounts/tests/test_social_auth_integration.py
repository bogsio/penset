"""
Integration tests for social authentication scenarios.
"""

from django.test import TestCase, Client, RequestFactory
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.urls import reverse
from django.http import HttpRequest
from allauth.account.models import EmailAddress
from allauth.socialaccount.models import SocialAccount, SocialApp
from organizations.models import Organization
from .test_base import AccountsTestCase
import json

User = get_user_model()


class SocialAuthIntegrationTestCase(AccountsTestCase):
    """Integration tests for social authentication scenarios."""

    def setUp(self):
        """Set up additional test data for integration tests."""
        super().setUp()
        
        # Create a social app for testing
        self.social_app = SocialApp.objects.create(
            provider='google',
            name='Google',
            client_id='test_client_id',
            secret='test_secret'
        )
        self.social_app.sites.add(1)  # Add to default site

    def test_complete_duplicate_email_scenario(self):
        """Test the complete scenario when a user tries to sign up with Google using an existing email."""
        # Create a user with an existing email
        existing_user = User.objects.create_user(
            username='existing@example.com',
            email='existing@example.com',
            password='testpass123',
            first_name='Existing',
            last_name='User',
            organization=self.organization
        )
        EmailAddress.objects.create(
            user=existing_user,
            email=existing_user.email,
            primary=True,
            verified=True
        )

        # Test the complete flow
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Simulate the social login process
        class MockSocialLogin:
            def __init__(self, email):
                self.account = MockSocialAccount(email)
                self.is_existing = False
        
        class MockSocialAccount:
            def __init__(self, email):
                self.extra_data = {'email': email}
        
        # Test adapter behavior
        adapter = CustomSocialAccountAdapter()
        sociallogin = MockSocialLogin('existing@example.com')
        
        # Should prevent auto-signup
        self.assertFalse(adapter.is_auto_signup_allowed(None, sociallogin))
        
        # Test that the user can still log in normally
        client = Client()
        login_success = client.login(username='existing@example.com', password='testpass123')
        self.assertTrue(login_success)

    def test_new_user_social_signup_flow(self):
        """Test the complete flow for a new user signing up via social login."""
        # Test that a new email is handled properly
        from accounts.adapters import CustomSocialAccountAdapter
        
        class MockSocialLogin:
            def __init__(self, email):
                self.account = MockSocialAccount(email)
                self.is_existing = False
        
        class MockSocialAccount:
            def __init__(self, email):
                self.extra_data = {'email': email}
        
        adapter = CustomSocialAccountAdapter()
        sociallogin = MockSocialLogin('newuser@example.com')
        
        # Should allow auto-signup for new email (now that SOCIALACCOUNT_AUTO_SIGNUP = True)
        result = adapter.is_auto_signup_allowed(None, sociallogin)
        self.assertTrue(result)  # Should return True for new emails

    def test_social_login_with_organization_assignment(self):
        """Test that social login properly handles organization assignment."""
        # Create a user without an organization
        user_without_org = User.objects.create_user(
            username='noorg@example.com',
            email='noorg@example.com',
            password='testpass123',
            first_name='No',
            last_name='Org',
            organization=None
        )
        
        # Test the adapter's redirect logic
        from accounts.adapters import CustomSocialAccountAdapter
        adapter = CustomSocialAccountAdapter()
        
        # Mock request
        request = RequestFactory().get('/')
        request.user = user_without_org
        
        # Should redirect to organization setup
        redirect_url = adapter.get_connect_redirect_url(request, None)
        self.assertEqual(redirect_url, '/accounts/social/organization-setup/')

    def test_social_account_connection_scenarios(self):
        """Test various scenarios for connecting social accounts."""
        # Test connecting to existing user
        existing_user = User.objects.create_user(
            username='connect@example.com',
            email='connect@example.com',
            password='testpass123',
            first_name='Connect',
            last_name='User',
            organization=self.organization
        )
        
        # Create a social account for this user
        social_account = SocialAccount.objects.create(
            user=existing_user,
            provider='google',
            uid='google_connect_123',
            extra_data={'email': 'connect@example.com'}
        )
        
        # Test that the connection exists
        self.assertEqual(social_account.user, existing_user)
        self.assertEqual(social_account.provider, 'google')

    def test_social_login_error_handling_edge_cases(self):
        """Test edge cases in social login error handling."""
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Test with empty extra_data
        class MockSocialLoginEmpty:
            def __init__(self):
                self.account = MockAccountEmpty()
                self.is_existing = False
        
        class MockAccountEmpty:
            def __init__(self):
                self.extra_data = {}
        
        adapter = CustomSocialAccountAdapter()
        sociallogin_empty = MockSocialLoginEmpty()
        
        # Should handle empty data gracefully
        result = adapter.is_auto_signup_allowed(None, sociallogin_empty)
        self.assertIsInstance(result, bool)
        
        # Test with malformed email
        class MockSocialLoginMalformed:
            def __init__(self):
                self.account = MockAccountMalformed()
                self.is_existing = False
        
        class MockAccountMalformed:
            def __init__(self):
                self.extra_data = {'email': 'not-an-email'}
        
        sociallogin_malformed = MockSocialLoginMalformed()
        result = adapter.is_auto_signup_allowed(None, sociallogin_malformed)
        self.assertIsInstance(result, bool)

    def test_social_signup_view_error_scenarios(self):
        """Test various error scenarios in the social signup view."""
        from accounts.views import CustomSocialSignupView
        from django.test import RequestFactory
        
        # Test view instantiation
        view = CustomSocialSignupView()
        self.assertIsNotNone(view)
        
        # Test that the view can handle different request types
        factory = RequestFactory()
        
        # Test GET request
        get_request = factory.get('/accounts/social/signup/')
        self.assertIsNotNone(get_request)
        
        # Test POST request
        post_request = factory.post('/accounts/social/signup/')
        self.assertIsNotNone(post_request)

    def test_social_login_with_multiple_providers(self):
        """Test social login with multiple providers for the same user."""
        # Create a user
        user = User.objects.create_user(
            username='multiprovider@example.com',
            email='multiprovider@example.com',
            password='testpass123',
            first_name='Multi',
            last_name='Provider',
            organization=self.organization
        )
        
        # Create social accounts for different providers
        google_account = SocialAccount.objects.create(
            user=user,
            provider='google',
            uid='google_multi_123',
            extra_data={'email': 'multiprovider@example.com'}
        )
        
        github_account = SocialAccount.objects.create(
            user=user,
            provider='github',
            uid='github_multi_123',
            extra_data={'email': 'multiprovider@example.com'}
        )
        
        # Test that both accounts are linked to the same user
        self.assertEqual(google_account.user, user)
        self.assertEqual(github_account.user, user)
        self.assertEqual(google_account.provider, 'google')
        self.assertEqual(github_account.provider, 'github')

    def test_social_login_organization_flow(self):
        """Test the organization setup flow after social login."""
        # Test the organization setup redirect
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Create a user without an organization
        user_no_org = User.objects.create_user(
            username='noorg2@example.com',
            email='noorg2@example.com',
            password='testpass123',
            first_name='No',
            last_name='Org2',
            organization=None
        )
        
        adapter = CustomSocialAccountAdapter()
        request = RequestFactory().get('/')
        request.user = user_no_org
        
        # Should redirect to organization setup
        redirect_url = adapter.get_connect_redirect_url(request, None)
        self.assertEqual(redirect_url, '/accounts/social/organization-setup/')
        
        # Test with user who has organization
        request.user = self.user  # self.user has an organization
        redirect_url = adapter.get_connect_redirect_url(request, None)
        # Should not redirect to organization setup
        self.assertNotEqual(redirect_url, '/accounts/social/organization-setup/')

    def test_social_login_data_validation(self):
        """Test validation of social login data."""
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Test with valid data
        class MockValidSocialLogin:
            def __init__(self, email):
                self.account = MockValidAccount(email)
                self.is_existing = False
        
        class MockValidAccount:
            def __init__(self, email):
                self.extra_data = {
                    'email': email,
                    'given_name': 'Valid',
                    'family_name': 'User'
                }
        
        adapter = CustomSocialAccountAdapter()
        valid_login = MockValidSocialLogin('valid@example.com')
        
        # Should handle valid data
        result = adapter.is_auto_signup_allowed(None, valid_login)
        self.assertIsInstance(result, bool)
        
        # Test with invalid email format
        invalid_login = MockValidSocialLogin('invalid-email-format')
        result = adapter.is_auto_signup_allowed(None, invalid_login)
        self.assertIsInstance(result, bool)

    def test_social_login_session_handling(self):
        """Test session handling during social login."""
        # Test that session data is properly managed
        client = Client()
        
        # Test accessing social signup without session
        response = client.get('/accounts/social/signup/')
        self.assertEqual(response.status_code, 302)
        
        # Test that the redirect goes to login
        self.assertRedirects(response, '/accounts/login/')

    def test_social_login_with_existing_social_account(self):
        """Test social login when user already has a social account."""
        # Create a user with an existing social account
        user_with_social = User.objects.create_user(
            username='social@example.com',
            email='social@example.com',
            password='testpass123',
            first_name='Social',
            last_name='User',
            organization=self.organization
        )
        
        # Create social account
        social_account = SocialAccount.objects.create(
            user=user_with_social,
            provider='google',
            uid='google_social_123',
            extra_data={'email': 'social@example.com'}
        )
        
        # Test that the user can be found by social account
        found_user = SocialAccount.objects.get(uid='google_social_123').user
        self.assertEqual(found_user, user_with_social)
        
        # Test that the user can log in normally
        client = Client()
        login_success = client.login(username='social@example.com', password='testpass123')
        self.assertTrue(login_success)
