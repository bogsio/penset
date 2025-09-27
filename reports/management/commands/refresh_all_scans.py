"""
Management command to refresh all scan results by reparsing their archives.
Usage: python manage.py refresh_all_scans
"""

from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.db import transaction
from reports.models import ScanSession
import os


class Command(BaseCommand):
    help = 'Refresh all scan results by reparsing their archives'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be refreshed without making changes'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force refresh even if archive file is missing'
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        force = options['force']
        
        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No changes will be made'))
        
        # Get all scan sessions
        scan_sessions = ScanSession.objects.all().order_by('-created_at')
        total_scans = scan_sessions.count()
        
        self.stdout.write(f'Found {total_scans} scan sessions to refresh')
        
        if total_scans == 0:
            self.stdout.write(self.style.WARNING('No scan sessions found'))
            return
        
        successful_refreshes = 0
        failed_refreshes = 0
        skipped_scans = 0
        
        for scan in scan_sessions:
            self.stdout.write(f'\nProcessing scan: {scan.description} (ID: {scan.id})')
            
            # Check if archive file exists
            if not scan.archive_file:
                if force:
                    self.stdout.write(
                        self.style.WARNING(f'  No archive file, but --force specified. Skipping...')
                    )
                    skipped_scans += 1
                    continue
                else:
                    self.stdout.write(
                        self.style.ERROR(f'  No archive file found for scan')
                    )
                    failed_refreshes += 1
                    continue
            
            # Check if file exists using storage
            try:
                if not scan.archive_file.storage.exists(scan.archive_file.name):
                    if force:
                        self.stdout.write(
                            self.style.WARNING(f'  Archive file missing, but --force specified. Skipping...')
                        )
                        skipped_scans += 1
                        continue
                    else:
                        self.stdout.write(
                            self.style.ERROR(f'  Archive file missing: {scan.archive_file.name}')
                        )
                        failed_refreshes += 1
                        continue
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'  Error checking archive file: {str(e)}')
                )
                failed_refreshes += 1
                continue
            
            if dry_run:
                self.stdout.write(f'  Would refresh scan: {scan.description}')
                successful_refreshes += 1
                continue
            
            try:
                # Call the reparse_scan command
                call_command(
                    'reparse_scan',
                    str(scan.id),
                    force=True,
                    verbosity=0  # Suppress output from reparse_scan
                )
                self.stdout.write(
                    self.style.SUCCESS(f'  ✓ Successfully refreshed: {scan.description}')
                )
                successful_refreshes += 1
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'  ✗ Failed to refresh: {scan.description} - {str(e)}')
                )
                failed_refreshes += 1
        
        # Summary
        self.stdout.write(f'\n{"="*50}')
        self.stdout.write(f'REFRESH SUMMARY')
        self.stdout.write(f'{"="*50}')
        self.stdout.write(f'Total scans: {total_scans}')
        self.stdout.write(f'Successful: {successful_refreshes}')
        self.stdout.write(f'Failed: {failed_refreshes}')
        self.stdout.write(f'Skipped: {skipped_scans}')
        
        if not dry_run:
            if failed_refreshes == 0:
                self.stdout.write(
                    self.style.SUCCESS('\n✓ All scan results refreshed successfully!')
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'\n⚠ {failed_refreshes} scans failed to refresh. Check the errors above.')
                )
