"""
Management command to reparse an existing scan archive and refresh the results.
Usage: python manage.py reparse_scan <scan_id> [--force]
"""

import zipfile
import tempfile
import os
import json
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from reports.models import ScanSession, Target, ScanResult, ScanArtifact


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

        # Clear existing data
        self.stdout.write('Clearing existing data...')
        with transaction.atomic():
            # Delete existing results, targets, and artifacts
            targets_count = scan_session.targets.count()
            results_count = scan_session.results.count()
            artifacts_count = scan_session.artifacts.count()

            scan_session.targets.all().delete()
            scan_session.results.all().delete()
            scan_session.artifacts.all().delete()

            self.stdout.write(f'Deleted {targets_count} targets, {results_count} results, {artifacts_count} artifacts')

            # Update status
            scan_session.status = 'processing'
            scan_session.error_message = ''
            scan_session.save()

        # Process the archive
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract ZIP file
                extract_path = os.path.join(temp_dir, 'extracted')
                with scan_session.archive_file.open('rb') as archive_file:
                    with zipfile.ZipFile(archive_file, 'r') as zip_ref:
                        zip_ref.extractall(extract_path)

                self.stdout.write('Processing archive contents...')

                # Process files
                self.process_summary_reports(scan_session, extract_path)
                self.process_domains(scan_session, extract_path)
                self.process_ips(scan_session, extract_path)
                self.process_ports(scan_session, extract_path)
                self.process_services(scan_session, extract_path)
                self.process_web_enumeration(scan_session, extract_path)
                self.process_vulnerabilities(scan_session, extract_path)
                self.process_exploits(scan_session, extract_path)

                # Update status
                scan_session.status = 'completed'
                scan_session.save()

                self.stdout.write(
                    self.style.SUCCESS(
                        f'Successfully reparsed scan results!\n'
                        f'Targets: {scan_session.targets.count()}\n'
                        f'Results: {scan_session.results.count()}\n'
                        f'Artifacts: {scan_session.artifacts.count()}'
                    )
                )

        except Exception as e:
            scan_session.status = 'failed'
            scan_session.error_message = str(e)
            scan_session.save()
            raise CommandError(f'Error processing archive: {str(e)}')

    def process_summary_reports(self, scan_session, extract_path):
        """Process summary report files"""
        summary_files = [
            ('enriched_summary_report.json', 'reconnaissance', 'reconnaissance_summary'),
            ('vulnerability_summary_report.json', 'vulnerability', 'vulnerability_summary'),
            ('exploitation_summary_report.json', 'exploitation', 'exploitation_summary')
        ]

        for filename, result_type, tool_name in summary_files:
            file_path = os.path.join(extract_path, filename)
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = json.load(f)

                ScanResult.objects.create(
                    scan_session=scan_session,
                    result_type=result_type,
                    tool_name=tool_name,
                    data=data,
                    severity='info'
                )
                self.stdout.write(f'Processed: {filename}')

    def process_domains(self, scan_session, extract_path):
        """Process discovered domains"""
        domains_file = os.path.join(extract_path, 'domains', 'all_domains.txt')
        if os.path.exists(domains_file):
            with open(domains_file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]

            for domain in domains:
                target, created = Target.objects.get_or_create(
                    scan_session=scan_session,
                    value=domain,
                    defaults={
                        'target_type': 'domain',
                        'discovered_by': 'subfinder',
                        'is_primary': False
                    }
                )

                if created:
                    ScanResult.objects.create(
                        scan_session=scan_session,
                        result_type='reconnaissance',
                        tool_name='subfinder',
                        data={'domain': domain},
                        target=target,
                        severity='info'
                    )
            self.stdout.write(f'Processed {len(domains)} domains')

    def process_ips(self, scan_session, extract_path):
        """Process discovered IP addresses"""
        ips_file = os.path.join(extract_path, 'ips', 'all_ips.txt')
        if os.path.exists(ips_file):
            with open(ips_file, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]

            for ip in ips:
                target, created = Target.objects.get_or_create(
                    scan_session=scan_session,
                    value=ip,
                    defaults={
                        'target_type': 'ip',
                        'discovered_by': 'dns_resolution',
                        'is_primary': False
                    }
                )

                if created:
                    ScanResult.objects.create(
                        scan_session=scan_session,
                        result_type='reconnaissance',
                        tool_name='dns_resolver',
                        data={'ip': ip},
                        target=target,
                        severity='info'
                    )
            self.stdout.write(f'Processed {len(ips)} IP addresses')

    def process_ports(self, scan_session, extract_path):
        """Process port scanning results"""
        ports_file = os.path.join(extract_path, 'ports', 'open_ports.json')
        if os.path.exists(ports_file):
            with open(ports_file, 'r') as f:
                ports_data = json.load(f)

            for ip, ports in ports_data.items():
                target = Target.objects.filter(
                    scan_session=scan_session,
                    value=ip,
                    target_type='ip'
                ).first()

                if target:
                    ScanResult.objects.create(
                        scan_session=scan_session,
                        result_type='reconnaissance',
                        tool_name='nmap',
                        data={'ip': ip, 'open_ports': ports},
                        target=target,
                        severity='info'
                    )
            self.stdout.write(f'Processed port data for {len(ports_data)} IPs')

    def process_services(self, scan_session, extract_path):
        """Process service detection results"""
        services_file = os.path.join(extract_path, 'services', 'detected_services.json')
        if os.path.exists(services_file):
            with open(services_file, 'r') as f:
                services_data = json.load(f)

            for ip, services in services_data.items():
                target = Target.objects.filter(
                    scan_session=scan_session,
                    value=ip,
                    target_type='ip'
                ).first()

                if target:
                    ScanResult.objects.create(
                        scan_session=scan_session,
                        result_type='reconnaissance',
                        tool_name='nmap_service_detection',
                        data={'ip': ip, 'services': services},
                        target=target,
                        severity='info'
                    )
            self.stdout.write(f'Processed service data for {len(services_data)} IPs')

    def process_web_enumeration(self, scan_session, extract_path):
        """Process web enumeration results"""
        web_file = os.path.join(extract_path, 'web', 'web_enumeration.json')
        if os.path.exists(web_file):
            with open(web_file, 'r') as f:
                web_data = json.load(f)

            for url, data in web_data.items():
                target, created = Target.objects.get_or_create(
                    scan_session=scan_session,
                    value=url,
                    defaults={
                        'target_type': 'url',
                        'discovered_by': 'web_enumeration',
                        'is_primary': False
                    }
                )

                if created:
                    ScanResult.objects.create(
                        scan_session=scan_session,
                        result_type='reconnaissance',
                        tool_name='gobuster',
                        data={'url': url, 'enumeration_data': data},
                        target=target,
                        severity='info'
                    )
            self.stdout.write(f'Processed {len(web_data)} web services')

    def process_vulnerabilities(self, scan_session, extract_path):
        """Process vulnerability results"""
        vuln_files = [
            ('vulnerabilities/nuclei_results.json', 'nuclei'),
            ('vulnerabilities/nikto_results.json', 'nikto'),
            ('vulnerabilities/sqlmap_results.json', 'sqlmap'),
            ('vulnerabilities/ssl_scan_results.json', 'ssl_scan')
        ]

        total_vulns = 0
        for file_path, tool_name in vuln_files:
            full_path = os.path.join(extract_path, file_path)
            if os.path.exists(full_path):
                with open(full_path, 'r') as f:
                    vuln_data = json.load(f)

                count = self.create_vulnerability_results(scan_session, vuln_data, tool_name)
                total_vulns += count
                if count > 0:
                    self.stdout.write(f'Processed {count} vulnerabilities from {tool_name}')

        if total_vulns > 0:
            self.stdout.write(f'Total vulnerabilities processed: {total_vulns}')

    def create_vulnerability_results(self, scan_session, vuln_data, tool_name):
        """Create vulnerability results from data"""
        count = 0
        if isinstance(vuln_data, list):
            for vuln in vuln_data:
                self.create_vulnerability_result(scan_session, vuln, tool_name)
                count += 1
        elif isinstance(vuln_data, dict):
            for target, vulns in vuln_data.items():
                if isinstance(vulns, list):
                    for vuln in vulns:
                        self.create_vulnerability_result(scan_session, vuln, tool_name)
                        count += 1
        return count

    def create_vulnerability_result(self, scan_session, vuln_data, tool_name):
        """Create vulnerability result from data"""
        target_value = vuln_data.get('target', vuln_data.get('host', ''))
        severity = vuln_data.get('severity', 'info')

        target = None
        if target_value:
            target, _ = Target.objects.get_or_create(
                scan_session=scan_session,
                value=target_value,
                defaults={
                    'target_type': 'url' if target_value.startswith(('http://', 'https://')) else 'ip',
                    'discovered_by': tool_name,
                    'is_primary': False
                }
            )

        ScanResult.objects.create(
            scan_session=scan_session,
            result_type='vulnerability',
            tool_name=tool_name,
            data=vuln_data,
            target=target,
            severity=severity
        )

    def process_exploits(self, scan_session, extract_path):
        """Process exploitation results"""
        exploit_files = [
            'exploit_results/successful_exploits.json',
            'exploit_results/failed_exploits.json',
            'exploit_results/exploit_attempts.json'
        ]

        total_exploits = 0
        for file_path in exploit_files:
            full_path = os.path.join(extract_path, file_path)
            if os.path.exists(full_path):
                with open(full_path, 'r') as f:
                    exploit_data = json.load(f)

                count = self.create_exploit_results(scan_session, exploit_data, file_path)
                total_exploits += count

        # Process exploit scripts
        exploits_dir = os.path.join(extract_path, 'exploits')
        if os.path.exists(exploits_dir):
            script_count = 0
            for filename in os.listdir(exploits_dir):
                if filename.endswith('.py'):
                    file_path = os.path.join(exploits_dir, filename)
                    file_size = os.path.getsize(file_path)

                    ScanArtifact.objects.create(
                        scan_session=scan_session,
                        artifact_type='exploit_script',
                        name=filename,
                        s3_key=f"imported/{scan_session.description or scan_session.id}/exploits/{filename}",
                        file_size=file_size,
                        mime_type='text/x-python',
                        description=f"Exploit script: {filename}"
                    )
                    script_count += 1
            if script_count > 0:
                self.stdout.write(f'Processed {script_count} exploit scripts')

        if total_exploits > 0:
            self.stdout.write(f'Total exploits processed: {total_exploits}')

    def create_exploit_results(self, scan_session, exploit_data, file_path):
        """Create exploitation results from data"""
        count = 0
        if isinstance(exploit_data, list):
            for exploit in exploit_data:
                self.create_exploit_result(scan_session, exploit, file_path)
                count += 1
        elif isinstance(exploit_data, dict):
            for target, exploits in exploit_data.items():
                if isinstance(exploits, list):
                    for exploit in exploits:
                        self.create_exploit_result(scan_session, exploit, file_path)
                        count += 1
        return count

    def create_exploit_result(self, scan_session, exploit_data, file_path):
        """Create exploitation result from data"""
        target_value = exploit_data.get('target', '')
        severity = exploit_data.get('severity', 'info')
        success = exploit_data.get('success', False)

        target = None
        if target_value:
            target, _ = Target.objects.get_or_create(
                scan_session=scan_session,
                value=target_value,
                defaults={
                    'target_type': 'url' if target_value.startswith(('http://', 'https://')) else 'ip',
                    'discovered_by': 'exploitation',
                    'is_primary': False
                }
            )

        result = ScanResult.objects.create(
            scan_session=scan_session,
            result_type='exploitation',
            tool_name='custom_exploit',
            data=exploit_data,
            target=target,
            severity=severity
        )

        # Create artifact for exploit script if referenced
        if 'exploit_script_path' in exploit_data:
            script_name = exploit_data['exploit_script_path'].split('/')[-1]
            ScanArtifact.objects.create(
                scan_session=scan_session,
                result=result,
                artifact_type='exploit_script',
                name=script_name,
                s3_key=f"imported/{scan_session.description or scan_session.id}/exploits/{script_name}",
                file_size=0,  # We don't have the actual file size here
                mime_type='text/x-python',
                description=f"Exploit script for {exploit_data.get('vulnerability', 'unknown vulnerability')}"
            )
