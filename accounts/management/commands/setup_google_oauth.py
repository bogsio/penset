"""
Management command to set up Google OAuth provider.
"""

from django.core.management.base import BaseCommand
from django.contrib.sites.models import Site
from allauth.socialaccount.models import SocialApp
import os


class Command(BaseCommand):
    help = 'Set up Google OAuth provider'

    def handle(self, *args, **options):
        # Get or create the default site
        site, created = Site.objects.get_or_create(
            id=1,
            defaults={
                'domain': 'localhost:8001',
                'name': 'Penset Development'
            }
        )
        
        if created:
            self.stdout.write(
                self.style.SUCCESS('Created default site: localhost:8001')
            )
        else:
            self.stdout.write(
                self.style.SUCCESS('Using existing site: {}'.format(site.domain))
            )

        # Get Google OAuth credentials from environment
        google_client_id = os.getenv('GOOGLE_CLIENT_ID', 'your-google-client-id-here')
        google_client_secret = os.getenv('GOOGLE_CLIENT_SECRET', 'your-google-client-secret-here')

        if google_client_id == 'your-google-client-id-here':
            self.stdout.write(
                self.style.WARNING(
                    'Google OAuth credentials not set in environment variables. '
                    'Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your .env file.'
                )
            )
            return

        # Create or update Google OAuth app
        google_app, created = SocialApp.objects.get_or_create(
            provider='google',
            name='Google',
            defaults={
                'client_id': google_client_id,
                'secret': google_client_secret,
            }
        )

        if not created:
            # Update existing app with new credentials
            google_app.client_id = google_client_id
            google_app.secret = google_client_secret
            google_app.save()

        # Add the site to the app
        google_app.sites.add(site)

        if created:
            self.stdout.write(
                self.style.SUCCESS('Google OAuth app created successfully!')
            )
        else:
            self.stdout.write(
                self.style.SUCCESS('Google OAuth app updated successfully!')
            )

        self.stdout.write(
            self.style.SUCCESS(
                'Google OAuth is now configured. You can test it at: '
                'http://localhost:8001/accounts/login/'
            )
        )



