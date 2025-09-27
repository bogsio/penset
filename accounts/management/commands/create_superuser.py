from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from organizations.models import Organization

User = get_user_model()


class Command(BaseCommand):
    help = 'Create a superuser with organization'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, help='Username')
        parser.add_argument('--email', type=str, help='Email')
        parser.add_argument('--password', type=str, help='Password')
        parser.add_argument('--organization', type=str, help='Organization name')

    def handle(self, *args, **options):
        username = options.get('username') or input('Username: ')
        email = options.get('email') or input('Email: ')
        password = options.get('password') or input('Password: ')
        organization_name = options.get('organization') or input('Organization name: ')

        # Create or get organization
        organization, created = Organization.objects.get_or_create(
            name=organization_name,
            defaults={'description': f'Organization for {organization_name}'}
        )

        if created:
            self.stdout.write(
                self.style.SUCCESS(f'Created organization: {organization.name}')
            )

        # Create superuser
        user = User.objects.create_superuser(
            username=username,
            email=email,
            password=password,
            organization=organization,
            role='admin'
        )

        self.stdout.write(
            self.style.SUCCESS(f'Successfully created superuser: {user.username}')
        )
