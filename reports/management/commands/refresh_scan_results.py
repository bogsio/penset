"""
Management command to refresh scan results and update service detection categorization.
Usage: python manage.py refresh_scan_results
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from django.db import models
from reports.models import ScanResult


class Command(BaseCommand):
    help = 'Refresh scan results and update service detection categorization'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be updated without making changes'
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        
        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No changes will be made'))
        
        # Update service detection results to use the new 'service' result type
        service_results = ScanResult.objects.filter(
            tool_name='nmap_service_detection',
            result_type='reconnaissance'
        )
        
        count = service_results.count()
        self.stdout.write(f'Found {count} service detection results to update')
        
        if count > 0:
            if dry_run:
                self.stdout.write('Would update the following service detection results:')
                for result in service_results[:5]:  # Show first 5 as examples
                    self.stdout.write(f'  - {result.id}: {result.target} ({result.scan_session.description})')
                if count > 5:
                    self.stdout.write(f'  ... and {count - 5} more')
            else:
                with transaction.atomic():
                    updated = service_results.update(result_type='service')
                    self.stdout.write(
                        self.style.SUCCESS(f'Successfully updated {updated} service detection results')
                    )
        
        # Show summary of current result types
        self.stdout.write('\nCurrent result type distribution:')
        result_types = ScanResult.objects.values('result_type').annotate(
            count=models.Count('id')
        ).order_by('-count')
        
        for rt in result_types:
            self.stdout.write(f'  {rt["result_type"]}: {rt["count"]} results')
        
        if not dry_run:
            self.stdout.write(
                self.style.SUCCESS('\nScan results refresh completed successfully!')
            )
