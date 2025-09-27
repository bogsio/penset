"""
Management command to import scan results from a ZIP file.
Usage: python manage.py import_scan_results <zip_file> --name "Scan Name" --description "Description"
"""

import os
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from reports.models import ScanSession
from reports.importers import import_scan_from_zip_file

User = get_user_model()


class Command(BaseCommand):
    help = 'Import scan results from a ZIP file'

    def add_arguments(self, parser):
        parser.add_argument('zip_file', type=str, help='Path to the ZIP file containing scan results')
        parser.add_argument('--name', type=str, required=True, help='Name for the scan session')
        parser.add_argument('--description', type=str, default='', help='Description for the scan session')
        parser.add_argument('--user', type=str, default='admin', help='Username of the user to create the scan session')

    def handle(self, *args, **options):
        zip_file_path = options['zip_file']
        name = options['name']
        description = options['description']
        username = options['user']

        # Validate ZIP file
        if not os.path.exists(zip_file_path):
            raise CommandError(f'ZIP file does not exist: {zip_file_path}')

        if not zip_file_path.endswith('.zip'):
            raise CommandError('File must be a ZIP archive')

        # Get user
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError(f'User does not exist: {username}')

        # Create scan session
        scan_session = ScanSession.objects.create(
            description=description or name,  # Use name as description if description is empty
            organization=user.organization,
            created_by=user,
            status='uploaded'
        )

        self.stdout.write(f'Created scan session: {scan_session.description} (ID: {scan_session.id})')

        # Process the ZIP file using unified import system
        try:
            stats = import_scan_from_zip_file(scan_session, zip_file_path)
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully imported scan results!\n'
                    f'Targets added: {stats["targets_added"]} (total: {stats["total_targets"]})\n'
                    f'Results added: {stats["results_added"]} (total: {stats["total_results"]})\n'
                    f'Artifacts added: {stats["artifacts_added"]} (total: {stats["total_artifacts"]})'
                )
            )

        except Exception as e:
            raise CommandError(f'Error processing archive: {str(e)}')