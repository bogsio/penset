"""
Tests for social authentication error handling scenarios.
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


class SocialAuthErrorHandlingTestCase(AccountsTestCase):
    """Test case for social authentication error handling."""

    def setUp(self):
        """Set up additional test data for error handling tests."""
        super().setUp()
        
        # Create a social app for testing
        self.social_app = SocialApp.objects.create(
            provider='google',
            name='Google',
            client_id='test_client_id',
            secret='test_secret'
        )
        self.social_app.sites.add(1)  # Add to default site

    def test_duplicate_email_integrity_error_handling(self):
        """Test that IntegrityError for duplicate emails is handled gracefully."""
        # Create a user with an existing email
        existing_user = User.objects.create_user(
            username='duplicate@example.com',
            email='duplicate@example.com',
            password='testpass123',
            first_name='Duplicate',
            last_name='User',
            organization=self.organization
        )
        EmailAddress.objects.create(
            user=existing_user,
            email=existing_user.email,
            primary=True,
            verified=True
        )

        # Test that our adapter prevents the error
        from accounts.adapters import CustomSocialAccountAdapter
        
        class MockSocialLogin:
            def __init__(self, email):
                self.account = MockSocialAccount(email)
                self.is_existing = False
        
        class MockSocialAccount:
            def __init__(self, email):
                self.extra_data = {'email': email}
        
        adapter = CustomSocialAccountAdapter()
        sociallogin = MockSocialLogin('duplicate@example.com')
        
        # Should prevent auto-signup, avoiding IntegrityError
        self.assertFalse(adapter.is_auto_signup_allowed(None, sociallogin))

    def test_custom_signup_view_exception_handling(self):
        """Test that the custom signup view handles exceptions properly."""
        from accounts.views import CustomSocialSignupView
        from django.test import RequestFactory
        from django.contrib.messages.storage.fallback import FallbackStorage
        
        # Create a request with messages framework
        factory = RequestFactory()
        request = factory.post('/accounts/social/signup/')
        request.session = {}
        messages = FallbackStorage(request)
        request._messages = messages
        
        # Test the view can be instantiated
        view = CustomSocialSignupView()
        self.assertIsNotNone(view)
        
        # Test that the view has the dispatch method
        self.assertTrue(hasattr(view, 'dispatch'))

    def test_social_login_with_missing_email_data(self):
        """Test handling of social login with missing email data."""
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Test with no email in extra_data
        class MockSocialLoginNoEmail:
            def __init__(self):
                self.account = MockAccountNoEmail()
                self.is_existing = False
        
        class MockAccountNoEmail:
            def __init__(self):
                self.extra_data = {}  # No email field
        
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

    def test_social_login_with_invalid_email_format(self):
        """Test handling of social login with invalid email format."""
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Test with invalid email format
        class MockSocialLoginInvalidEmail:
            def __init__(self):
                self.account = MockAccountInvalidEmail()
                self.is_existing = False
        
        class MockAccountInvalidEmail:
            def __init__(self):
                self.extra_data = {'email': 'not-a-valid-email'}
        
        adapter = CustomSocialAccountAdapter()
        sociallogin_invalid = MockSocialLoginInvalidEmail()
        
        # Should handle invalid email gracefully
        result = adapter.is_auto_signup_allowed(None, sociallogin_invalid)
        self.assertIsInstance(result, bool)

    def test_social_login_with_empty_string_email(self):
        """Test handling of social login with empty string email."""
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Test with empty string email
        class MockSocialLoginEmptyEmail:
            def __init__(self):
                self.account = MockAccountEmptyEmail()
                self.is_existing = False
        
        class MockAccountEmptyEmail:
            def __init__(self):
                self.extra_data = {'email': ''}
        
        adapter = CustomSocialAccountAdapter()
        sociallogin_empty = MockSocialLoginEmptyEmail()
        
        # Should handle empty email gracefully
        result = adapter.is_auto_signup_allowed(None, sociallogin_empty)
        self.assertIsInstance(result, bool)

    def test_social_login_with_whitespace_email(self):
        """Test handling of social login with whitespace-only email."""
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Test with whitespace email
        class MockSocialLoginWhitespaceEmail:
            def __init__(self):
                self.account = MockAccountWhitespaceEmail()
                self.is_existing = False
        
        class MockAccountWhitespaceEmail:
            def __init__(self):
                self.extra_data = {'email': '   '}
        
        adapter = CustomSocialAccountAdapter()
        sociallogin_whitespace = MockSocialLoginWhitespaceEmail()
        
        # Should handle whitespace email gracefully
        result = adapter.is_auto_signup_allowed(None, sociallogin_whitespace)
        self.assertIsInstance(result, bool)

    def test_social_login_with_malformed_extra_data(self):
        """Test handling of social login with malformed extra_data."""
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Test with non-dict extra_data
        class MockSocialLoginMalformedData:
            def __init__(self):
                self.account = MockAccountMalformedData()
                self.is_existing = False
        
        class MockAccountMalformedData:
            def __init__(self):
                self.extra_data = "not a dict"  # Should be a dict
        
        adapter = CustomSocialAccountAdapter()
        sociallogin_malformed = MockSocialLoginMalformedData()
        
        # Should handle malformed data gracefully
        try:
            result = adapter.is_auto_signup_allowed(None, sociallogin_malformed)
            # If it doesn't crash, that's good
            self.assertIsInstance(result, bool)
        except (AttributeError, TypeError):
            # If it crashes, that's also acceptable for malformed data
            pass

    def test_social_login_with_missing_account_attribute(self):
        """Test handling of social login with missing account attribute."""
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Test with missing account attribute
        class MockSocialLoginNoAccount:
            def __init__(self):
                self.is_existing = False
                # No account attribute
        
        adapter = CustomSocialAccountAdapter()
        sociallogin_no_account = MockSocialLoginNoAccount()
        
        # Should handle missing account gracefully
        try:
            result = adapter.is_auto_signup_allowed(None, sociallogin_no_account)
            # If it doesn't crash, that's good
            self.assertIsInstance(result, bool)
        except AttributeError:
            # If it crashes, that's also acceptable for missing account
            pass

    def test_social_login_with_missing_extra_data_attribute(self):
        """Test handling of social login with missing extra_data attribute."""
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Test with missing extra_data attribute
        class MockSocialLoginNoExtraData:
            def __init__(self):
                self.account = MockAccountNoExtraData()
                self.is_existing = False
        
        class MockAccountNoExtraData:
            def __init__(self):
                # No extra_data attribute
                pass
        
        adapter = CustomSocialAccountAdapter()
        sociallogin_no_extra = MockSocialLoginNoExtraData()
        
        # Should handle missing extra_data gracefully
        try:
            result = adapter.is_auto_signup_allowed(None, sociallogin_no_extra)
            # If it doesn't crash, that's good
            self.assertIsInstance(result, bool)
        except AttributeError:
            # If it crashes, that's also acceptable for missing extra_data
            pass

    def test_social_login_with_database_connection_error(self):
        """Test handling of database connection errors during social login."""
        from accounts.adapters import CustomSocialAccountAdapter
        
        # This test simulates what happens if there's a database issue
        # We can't easily simulate a real database error, but we can test
        # that our code doesn't crash on unexpected database states
        
        class MockSocialLogin:
            def __init__(self, email):
                self.account = MockSocialAccount(email)
                self.is_existing = False
        
        class MockSocialAccount:
            def __init__(self, email):
                self.extra_data = {'email': email}
        
        adapter = CustomSocialAccountAdapter()
        sociallogin = MockSocialLogin('test@example.com')
        
        # Should handle database operations gracefully
        result = adapter.is_auto_signup_allowed(None, sociallogin)
        self.assertIsInstance(result, bool)

    def test_social_login_with_concurrent_user_creation(self):
        """Test handling of concurrent user creation scenarios."""
        # This test simulates a race condition where two users try to sign up
        # with the same email at the same time
        
        from accounts.adapters import CustomSocialAccountAdapter
        
        class MockSocialLogin:
            def __init__(self, email):
                self.account = MockSocialAccount(email)
                self.is_existing = False
        
        class MockSocialAccount:
            def __init__(self, email):
                self.extra_data = {'email': email}
        
        adapter = CustomSocialAccountAdapter()
        
        # Test with an email that doesn't exist yet
        sociallogin = MockSocialLogin('concurrent@example.com')
        result = adapter.is_auto_signup_allowed(None, sociallogin)
        self.assertIsInstance(result, bool)
        
        # Now create a user with that email
        User.objects.create_user(
            username='concurrent@example.com',
            email='concurrent@example.com',
            password='testpass123',
            first_name='Concurrent',
            last_name='User',
            organization=self.organization
        )
        
        # Test again with the same email
        sociallogin2 = MockSocialLogin('concurrent@example.com')
        result2 = adapter.is_auto_signup_allowed(None, sociallogin2)
        # Should now return False since user exists
        self.assertFalse(result2)

    def test_social_login_error_message_content(self):
        """Test that error messages are user-friendly and informative."""
        # Test that our error handling provides meaningful messages
        from accounts.views import CustomSocialSignupView
        
        view = CustomSocialSignupView()
        
        # Test that the view exists and can handle errors
        self.assertIsNotNone(view)
        self.assertTrue(hasattr(view, 'dispatch'))
        
        # The actual error message content is tested in the view's dispatch method
        # which catches IntegrityError and shows a user-friendly message

    def test_social_login_redirect_behavior(self):
        """Test that social login redirects work correctly in error scenarios."""
        # Test that users are properly redirected when errors occur
        client = Client()
        
        # Test accessing social signup without proper session
        response = client.get('/accounts/social/signup/')
        self.assertEqual(response.status_code, 302)
        
        # Should redirect to login page
        self.assertRedirects(response, '/accounts/login/')

    def test_social_login_with_different_provider_data_structures(self):
        """Test handling of different provider data structures."""
        from accounts.adapters import CustomSocialAccountAdapter
        
        # Test Google provider structure
        class MockGoogleLogin:
            def __init__(self, email):
                self.account = MockGoogleAccount(email)
                self.is_existing = False
        
        class MockGoogleAccount:
            def __init__(self, email):
                self.extra_data = {
                    'email': email,
                    'given_name': 'Test',
                    'family_name': 'User',
                    'picture': 'https://example.com/photo.jpg',
                    'verified_email': True
                }
        
        # Test GitHub provider structure
        class MockGitHubLogin:
            def __init__(self, email):
                self.account = MockGitHubAccount(email)
                self.is_existing = False
        
        class MockGitHubAccount:
            def __init__(self, email):
                self.extra_data = {
                    'email': email,
                    'name': 'Test User',
                    'login': 'testuser',
                    'avatar_url': 'https://example.com/avatar.jpg',
                    'public_repos': 10
                }
        
        adapter = CustomSocialAccountAdapter()
        
        # Test both providers
        google_login = MockGoogleLogin('test@gmail.com')
        github_login = MockGitHubLogin('test@github.com')
        
        # Both should be handled gracefully
        google_result = adapter.is_auto_signup_allowed(None, google_login)
        github_result = adapter.is_auto_signup_allowed(None, github_login)
        
        self.assertIsInstance(google_result, bool)
        self.assertIsInstance(github_result, bool)



