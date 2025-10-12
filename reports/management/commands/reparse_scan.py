"""
Management command to reparse an existing scan archive and refresh the results.
Usage: python manage.py reparse_scan <scan_id> [--force]
"""

from django.core.management.base import BaseCommand, CommandError
from reports.models import ScanSession


class Command(BaseCommand):
    help = 'Reparse an existing scan archive and refresh the results'

    def add_arguments(self, parser):
        parser.add_argument('scan_id', type=str, help='ID of the scan session to reparse')
        parser.add_argument('--force', action='store_true', help='Force reparse even if scan is not in uploaded status')
        parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')

    def handle(self, *args, **options):
        scan_id = options['scan_id']
        force = options['force']
        dry_run = options['dry_run']

        # Get scan session
        try:
            scan_session = ScanSession.objects.get(id=scan_id)
        except ScanSession.DoesNotExist:
            raise CommandError(f'Scan session does not exist: {scan_id}')

        # Check if scan can be reparsed
        if not force and scan_session.status not in ['uploaded', 'failed']:
            raise CommandError(
                f'Scan session is in "{scan_session.status}" status. '
                f'Use --force to reparse anyway.'
            )

        if not scan_session.archive_file:
            raise CommandError(f'Scan session {scan_id} has no archive file')

        self.stdout.write(f'Reparsing scan: {scan_session.description or scan_session.id}')
        self.stdout.write(f'Status: {scan_session.status}')
        self.stdout.write(f'Archive: {scan_session.archive_file.name}')

        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN - No changes will be made'))
            return

        # Get archive file
        if not scan_session.archive_file:
            raise CommandError('No archive file found for this scan session')
        
        # Check if file exists using storage
        if not scan_session.archive_file.storage.exists(scan_session.archive_file.name):
            raise CommandError(f'Archive file does not exist: {scan_session.archive_file.name}')

        # Use the reusable function to clear and reprocess
        self.stdout.write('Clearing existing data and reprocessing archive...')
        try:
            from reports.importers import clear_and_reprocess_scan_archive
            stats = clear_and_reprocess_scan_archive(scan_session)
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully reparsed scan results!\n'
                    f'Targets: {stats["total_targets"]} (added: {stats["targets_added"]})\n'
                    f'Results: {stats["total_results"]} (added: {stats["results_added"]})\n'
                    f'Artifacts: {stats["total_artifacts"]} (added: {stats["artifacts_added"]})'
                )
            )
            
        except Exception as e:
            raise CommandError(f'Error processing archive: {str(e)}')
