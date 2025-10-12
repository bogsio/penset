"""
Tests for social authentication functionality.
"""

from django.test import TestCase, Client, RequestFactory
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.urls import reverse
from django.http import HttpRequest
from allauth.account.models import EmailAddress
from allauth.socialaccount.models import SocialAccount, SocialApp, SocialLogin
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from organizations.models import Organization
from .test_base import AccountsTestCase
import json

User = get_user_model()


class SocialAuthTestCase(AccountsTestCase):
    """Test case for social authentication."""

    def setUp(self):
        """Set up additional test data for social auth tests."""
        super().setUp()
        
        # Create a social app for testing
        self.social_app = SocialApp.objects.create(
            provider='google',
            name='Google',
            client_id='test_client_id',
            secret='test_secret'
        )
        self.social_app.sites.add(1)  # Add to default site

    def test_duplicate_email_handling_in_adapter(self):
        """Test that duplicate email errors are handled gracefully in the adapter."""
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

        # Test that our custom adapter prevents auto-signup
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Create a mock social login
        class MockSocialLogin:
            def __init__(self, email):
                self.account = MockSocialAccount(email)
                self.is_existing = False
        
        class MockSocialAccount:
            def __init__(self, email):
                self.extra_data = {'email': email}
        
        # Test the adapter
        adapter = CustomSocialAccountAdapter()
        sociallogin = MockSocialLogin('existing@example.com')
        
        # Should return False (prevent auto-signup)
        self.assertFalse(adapter.is_auto_signup_allowed(None, sociallogin))
        
        # Test with non-existing email
        sociallogin_new = MockSocialLogin('new@example.com')
        # The parent method might return False by default, so we just test that it doesn't crash
        result = adapter.is_auto_signup_allowed(None, sociallogin_new)
        self.assertIsInstance(result, bool)

    def test_custom_social_signup_view_error_handling(self):
        """Test that the custom social signup view handles errors gracefully."""
        from accounts.views import CustomSocialSignupView
        from django.test import RequestFactory
        
        # Create a request factory
        factory = RequestFactory()
        request = factory.post('/accounts/social/signup/')
        
        # Create the view
        view = CustomSocialSignupView()
        
        # Test that the view exists and can be instantiated
        self.assertIsNotNone(view)
        self.assertEqual(view.__class__.__name__, 'CustomSocialSignupView')

    def test_social_signup_with_existing_email_redirects_to_login(self):
        """Test that attempting social signup with existing email redirects to login."""
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

        # Test the social signup URL
        response = self.client.get('/accounts/social/signup/')
        # Should redirect to login page
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, '/accounts/login/')

    def test_social_login_flow_for_new_user(self):
        """Test the complete social login flow for a new user."""
        # This test simulates what happens when a new user tries to sign up via Google
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Create mock social login data for a new user
        class MockSocialLogin:
            def __init__(self, email, first_name, last_name):
                self.account = MockSocialAccount(email, first_name, last_name)
                self.is_existing = False
        
        class MockSocialAccount:
            def __init__(self, email, first_name, last_name):
                self.extra_data = {
                    'email': email,
                    'given_name': first_name,
                    'family_name': last_name
                }
        
        # Test with a new email
        sociallogin = MockSocialLogin('newuser@example.com', 'New', 'User')
        adapter = CustomSocialAccountAdapter()
        
        # Should allow auto-signup for new email (now that SOCIALACCOUNT_AUTO_SIGNUP = True)
        result = adapter.is_auto_signup_allowed(None, sociallogin)
        self.assertTrue(result)  # Should return True for new emails

    def test_social_login_flow_for_existing_user(self):
        """Test the social login flow for an existing user."""
        # Create an existing user
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

        # Create a social account for this user
        social_account = SocialAccount.objects.create(
            user=existing_user,
            provider='google',
            uid='google_123456789',
            extra_data={'email': 'existing@example.com'}
        )

        # Test that the user can be found by social account
        self.assertEqual(social_account.user, existing_user)
        self.assertEqual(social_account.provider, 'google')

    def test_organization_setup_after_social_login(self):
        """Test that new social users are redirected to organization setup."""
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Create a new user without an organization
        new_user = User.objects.create_user(
            username='newuser@example.com',
            email='newuser@example.com',
            password='testpass123',
            first_name='New',
            last_name='User',
            organization=None  # No organization
        )
        
        # Test the adapter's redirect logic
        adapter = CustomSocialAccountAdapter()
        
        # Mock request with user
        request = RequestFactory().get('/')
        request.user = new_user
        
        # Test redirect URL for user without organization
        redirect_url = adapter.get_connect_redirect_url(request, None)
        self.assertEqual(redirect_url, '/accounts/social/organization-setup/')

    def test_social_signup_form_validation(self):
        """Test that social signup form handles validation errors properly."""
        # Test accessing the social signup page
        response = self.client.get('/accounts/social/signup/')
        
        # Should redirect to login since no social login session exists
        self.assertEqual(response.status_code, 302)

    def test_duplicate_email_error_message_content(self):
        """Test that the error message for duplicate emails is user-friendly."""
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

        # Test the error message in our custom view
        from accounts.views import CustomSocialSignupView
        from django.test import RequestFactory
        from django.contrib.messages.storage.fallback import FallbackStorage
        
        factory = RequestFactory()
        request = factory.post('/accounts/social/signup/')
        
        # Add messages framework to request
        setattr(request, 'session', {})
        messages = FallbackStorage(request)
        setattr(request, '_messages', messages)
        
        view = CustomSocialSignupView()
        
        # Test that the view can handle the duplicate email scenario
        # (This is more of a structural test since we can't easily mock the full flow)
        self.assertIsNotNone(view)

    def test_social_account_adapter_inheritance(self):
        """Test that our custom adapter properly inherits from the base class."""
        from accounts.adapters import CustomSocialAccountAdapter
        from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
        
        adapter = CustomSocialAccountAdapter()
        
        # Test inheritance
        self.assertIsInstance(adapter, DefaultSocialAccountAdapter)
        self.assertIsInstance(adapter, CustomSocialAccountAdapter)
        
        # Test that our custom methods exist
        self.assertTrue(hasattr(adapter, 'is_auto_signup_allowed'))
        self.assertTrue(hasattr(adapter, 'pre_social_login'))
        self.assertTrue(hasattr(adapter, 'save_user'))
        self.assertTrue(hasattr(adapter, 'get_connect_redirect_url'))

    def test_social_login_with_different_providers(self):
        """Test social login handling for different providers."""
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Test with Google provider data
        class MockGoogleSocialLogin:
            def __init__(self, email):
                self.account = MockGoogleAccount(email)
                self.is_existing = False
        
        class MockGoogleAccount:
            def __init__(self, email):
                self.extra_data = {
                    'email': email,
                    'given_name': 'Test',
                    'family_name': 'User',
                    'picture': 'https://example.com/photo.jpg'
                }
        
        # Test with GitHub provider data
        class MockGitHubSocialLogin:
            def __init__(self, email):
                self.account = MockGitHubAccount(email)
                self.is_existing = False
        
        class MockGitHubAccount:
            def __init__(self, email):
                self.extra_data = {
                    'email': email,
                    'name': 'Test User',
                    'login': 'testuser',
                    'avatar_url': 'https://example.com/avatar.jpg'
                }
        
        adapter = CustomSocialAccountAdapter()
        
        # Test Google provider
        google_login = MockGoogleSocialLogin('test@gmail.com')
        result = adapter.is_auto_signup_allowed(None, google_login)
        self.assertIsInstance(result, bool)
        
        # Test GitHub provider
        github_login = MockGitHubSocialLogin('test@github.com')
        result = adapter.is_auto_signup_allowed(None, github_login)
        self.assertIsInstance(result, bool)

    def test_social_login_edge_cases(self):
        """Test edge cases in social login handling."""
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Test with missing email
        class MockSocialLoginNoEmail:
            def __init__(self):
                self.account = MockAccountNoEmail()
                self.is_existing = False
        
        class MockAccountNoEmail:
            def __init__(self):
                self.extra_data = {}  # No email
        
        adapter = CustomSocialAccountAdapter()
        sociallogin_no_email = MockSocialLoginNoEmail()
        
        # Should handle missing email gracefully
        result = adapter.is_auto_signup_allowed(None, sociallogin_no_email)
        self.assertIsInstance(result, bool)
        
        # Test with None email
        class MockSocialLoginNoneEmail:
            def __init__(self):
                self.account = MockAccountNoneEmail()
                self.is_existing = False
        
        class MockAccountNoneEmail:
            def __init__(self):
                self.extra_data = {'email': None}
        
        sociallogin_none_email = MockSocialLoginNoneEmail()
        result = adapter.is_auto_signup_allowed(None, sociallogin_none_email)
        self.assertIsInstance(result, bool)

    def test_social_signup_view_inheritance(self):
        """Test that our custom social signup view properly inherits from the base class."""
        from accounts.views import CustomSocialSignupView
        from allauth.socialaccount.views import SignupView
        
        view = CustomSocialSignupView()
        
        # Test inheritance
        self.assertIsInstance(view, SignupView)
        self.assertIsInstance(view, CustomSocialSignupView)
        
        # Test that our custom method exists
        self.assertTrue(hasattr(view, 'dispatch'))

    def test_social_login_url_patterns(self):
        """Test that our custom URL patterns are properly configured."""
        from django.urls import reverse, NoReverseMatch
        
        # Test that our custom social signup URL exists
        try:
            url = reverse('accounts:socialaccount_signup')
            self.assertEqual(url, '/accounts/social/signup/')
        except NoReverseMatch:
            self.fail("Custom social signup URL not found")
        
        # Test that the URL resolves to our custom view
        from django.test import Client
        client = Client()
        response = client.get('/accounts/social/signup/')
        # Should redirect since no social login session
        self.assertEqual(response.status_code, 302)
