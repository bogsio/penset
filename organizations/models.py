from django.db import models
from django.core.validators import RegexValidator


class Organization(models.Model):
    """
    Organization model for grouping users and reports.
    """
    name = models.CharField(
        max_length=100,
        validators=[
            RegexValidator(
                regex=r'^[a-zA-Z0-9\s\-_]+$',
                message='Organization name can only contain letters, numbers, spaces, hyphens, and underscores.'
            )
        ]
    )
    description = models.TextField(blank=True, null=True)
    website = models.URLField(blank=True, null=True)
    contact_email = models.EmailField(blank=True, null=True)
    targets = models.TextField(
        blank=True, 
        null=True,
        help_text="Comma-separated list of target domains, IPs, or URLs for this organization"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = 'organizations'
        ordering = ['name']

    def __str__(self):
        return self.name

    @property
    def user_count(self):
        """Return the number of users in this organization"""
        return self.users.count()

    @property
    def admin_count(self):
        """Return the number of admins in this organization"""
        return self.users.filter(is_organization_admin=True).count()
