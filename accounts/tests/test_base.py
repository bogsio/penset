"""
Base test classes and utilities for accounts tests.
"""

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from allauth.account.models import EmailAddress
from organizations.models import Organization

User = get_user_model()


class AccountsTestCase(TestCase):
    """Base test case for accounts tests with common setup."""
    
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
        
        # Create verified email address for test user
        EmailAddress.objects.create(
            user=self.user,
            email=self.user.email,
            primary=True,
            verified=True
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
        
        # Create verified email address for test user 2
        EmailAddress.objects.create(
            user=self.user2,
            email=self.user2.email,
            primary=True,
            verified=True
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
        
        # Create verified email address for other user
        EmailAddress.objects.create(
            user=self.other_user,
            email=self.other_user.email,
            primary=True,
            verified=True
        )
        
        self.client = Client()
