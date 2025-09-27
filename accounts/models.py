from django.contrib.auth.models import AbstractUser
from django.db import models
from organizations.models import Organization


class User(AbstractUser):
    """
    Custom User model extending Django's AbstractUser.
    Each user belongs to an organization.
    """
    email = models.EmailField(unique=True)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='users',
        null=True,
        blank=True
    )
    role = models.CharField(
        max_length=50,
        choices=[
            ('admin', 'Administrator'),
            ('analyst', 'Security Analyst'),
            ('viewer', 'Viewer'),
        ],
        default='viewer'
    )
    is_organization_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    class Meta:
        db_table = 'users'

    def __str__(self):
        return f"{self.email} ({self.organization.name if self.organization else 'No Organization'})"

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    def can_manage_organization(self):
        """Check if user can manage their organization"""
        return self.is_organization_admin or self.role == 'admin'

    def can_view_reports(self):
        """Check if user can view reports"""
        return self.role in ['admin', 'analyst', 'viewer']

    def can_edit_reports(self):
        """Check if user can edit reports"""
        return self.role in ['admin', 'analyst']
