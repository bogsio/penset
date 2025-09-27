"""
Unified ZIP import system for scan results.
This module provides a single, consistent way to import scan results from ZIP files.
"""

import zipfile
import tempfile
import os
import json
import logging
from typing import Optional, Dict, Any
from django.core.exceptions import ValidationError
from .models import ScanSession, Target, ScanResult, ScanArtifact

logger = logging.getLogger(__name__)


class ScanImporter:
    """
    Unified importer for scan results from ZIP files.
    This class handles all ZIP processing logic in one place.
    """
    
    def __init__(self, scan_session: ScanSession):
        self.scan_session = scan_session
    
    def import_from_zip_file(self, zip_file_path: str) -> Dict[str, Any]:
        """
        Import scan results from a ZIP file path.
        
        Args:
            zip_file_path: Path to the ZIP file
            
        Returns:
            Dict with import statistics
        """
        if not os.path.exists(zip_file_path):
            raise ValidationError(f"ZIP file does not exist: {zip_file_path}")
        
        if not zip_file_path.endswith('.zip'):
            raise ValidationError("File must be a ZIP archive")
        
        return self._process_zip_file(zip_file_path)
    
    def import_from_uploaded_file(self, uploaded_file) -> Dict[str, Any]:
        """
        Import scan results from an uploaded file object.
        
        Args:
            uploaded_file: Django uploaded file object
            
        Returns:
            Dict with import statistics
        """
        if not uploaded_file.name.endswith('.zip'):
            raise ValidationError("Only ZIP files are supported")
        
        if uploaded_file.size > 100 * 1024 * 1024:  # 100MB limit
            raise ValidationError("Archive size cannot exceed 100MB")
        
        # Validate ZIP structure
        try:
            with zipfile.ZipFile(uploaded_file, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                if not any('enriched_summary_report.json' in f or 'vulnerability_summary_report.json' in f for f in file_list):
                    raise ValidationError("Archive does not appear to contain valid scan results")
        except zipfile.BadZipFile:
            raise ValidationError("Invalid ZIP file")
        
        # Save uploaded file temporarily and process
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_file:
            for chunk in uploaded_file.chunks():
                tmp_file.write(chunk)
            tmp_file.flush()
            
            try:
                return self._process_zip_file(tmp_file.name)
            finally:
                os.unlink(tmp_file.name)
    
    def _process_zip_file(self, zip_file_path: str) -> Dict[str, Any]:
        """
        Process a ZIP file and extract scan results.
        
        Args:
            zip_file_path: Path to the ZIP file
            
        Returns:
            Dict with import statistics
        """
        # Update scan session status
        self.scan_session.status = 'processing'
        self.scan_session.save()
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract ZIP file
                extract_path = os.path.join(temp_dir, 'extracted')
                with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
                
                # Process the extracted files
                stats = self._populate_models_from_files(extract_path)
                
                # Update status to completed
                self.scan_session.status = 'completed'
                self.scan_session.save()
                
                logger.info(f"Successfully processed archive for scan session {self.scan_session.id}")
                return stats
                
        except Exception as e:
            logger.error(f"Error processing archive: {str(e)}")
            self.scan_session.status = 'failed'
            self.scan_session.error_message = str(e)
            self.scan_session.save()
            raise ValidationError(f"Error processing archive: {str(e)}")
    
    def _populate_models_from_files(self, extract_path: str) -> Dict[str, Any]:
        """
        Populate models from extracted files.
        
        Args:
            extract_path: Path to the extracted files
            
        Returns:
            Dict with import statistics
        """
        initial_targets = self.scan_session.targets.count()
        initial_results = self.scan_session.results.count()
        initial_artifacts = self.scan_session.artifacts.count()
        
        # Process summary reports
        self._process_summary_reports(extract_path)
        
        # Process individual result files
        self._process_domains(extract_path)
        self._process_ips(extract_path)
        self._process_ports(extract_path)
        self._process_services(extract_path)
        self._process_web_enumeration(extract_path)
        self._process_vulnerabilities(extract_path)
        self._process_exploits(extract_path)
        
        # Calculate statistics
        final_targets = self.scan_session.targets.count()
        final_results = self.scan_session.results.count()
        final_artifacts = self.scan_session.artifacts.count()
        
        return {
            'targets_added': final_targets - initial_targets,
            'results_added': final_results - initial_results,
            'artifacts_added': final_artifacts - initial_artifacts,
            'total_targets': final_targets,
            'total_results': final_results,
            'total_artifacts': final_artifacts
        }
    
    def _process_summary_reports(self, extract_path: str):
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
                    scan_session=self.scan_session,
                    result_type=result_type,
                    tool_name=tool_name,
                    data=data,
                    severity='info'
                )
    
    def _process_domains(self, extract_path: str):
        """Process discovered domains"""
        domains_file = os.path.join(extract_path, 'domains', 'all_domains.txt')
        
        if os.path.exists(domains_file):
            with open(domains_file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            for domain in domains:
                target, created = Target.objects.get_or_create(
                    scan_session=self.scan_session,
                    value=domain,
                    defaults={
                        'target_type': 'domain',
                        'discovered_by': 'subfinder',
                        'is_primary': False
                    }
                )
                
                if created:
                    ScanResult.objects.create(
                        scan_session=self.scan_session,
                        result_type='reconnaissance',
                        tool_name='subfinder',
                        data={'domain': domain},
                        target=target,
                        severity='info'
                    )
    
    def _process_ips(self, extract_path: str):
        """Process discovered IP addresses"""
        ips_file = os.path.join(extract_path, 'ips', 'all_ips.txt')
        
        if os.path.exists(ips_file):
            with open(ips_file, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            
            for ip in ips:
                target, created = Target.objects.get_or_create(
                    scan_session=self.scan_session,
                    value=ip,
                    defaults={
                        'target_type': 'ip',
                        'discovered_by': 'dns_resolution',
                        'is_primary': False
                    }
                )
                
                if created:
                    ScanResult.objects.create(
                        scan_session=self.scan_session,
                        result_type='reconnaissance',
                        tool_name='dns_resolution',
                        data={'ip': ip},
                        target=target,
                        severity='info'
                    )
    
    def _process_ports(self, extract_path: str):
        """Process port scan results"""
        ports_file = os.path.join(extract_path, 'ports', 'all_ports.txt')
        
        if os.path.exists(ports_file):
            with open(ports_file, 'r') as f:
                ports = [line.strip() for line in f if line.strip()]
            
            for port_line in ports:
                if ':' in port_line:
                    ip, port = port_line.split(':', 1)
                    target, _ = Target.objects.get_or_create(
                        scan_session=self.scan_session,
                        value=ip,
                        defaults={
                            'target_type': 'ip',
                            'discovered_by': 'nmap',
                            'is_primary': False
                        }
                    )
                    
                    ScanResult.objects.create(
                        scan_session=self.scan_session,
                        result_type='reconnaissance',
                        tool_name='nmap',
                        data={'ip': ip, 'port': port},
                        target=target,
                        severity='info'
                    )
    
    def _process_services(self, extract_path: str):
        """Process service detection results"""
        # Try JSON format first (services/detected_services.json)
        services_json_file = os.path.join(extract_path, 'services', 'detected_services.json')
        services_txt_file = os.path.join(extract_path, 'services', 'all_services.txt')
        
        if os.path.exists(services_json_file):
            with open(services_json_file, 'r') as f:
                services_data = json.load(f)
            
            # Handle nested dictionary structure: {ip: {port: {service, version, state}}}
            if isinstance(services_data, dict):
                for ip, ports_data in services_data.items():
                    if isinstance(ports_data, dict):
                        for port_protocol, service_info in ports_data.items():
                            if isinstance(service_info, dict):
                                service = service_info.get('service', '')
                                version = service_info.get('version', '')
                                state = service_info.get('state', '')
                                
                                # Extract port number from "port/protocol" format
                                port = port_protocol.split('/')[0] if '/' in port_protocol else port_protocol
                                
                                target, _ = Target.objects.get_or_create(
                                    scan_session=self.scan_session,
                                    value=ip,
                                    defaults={
                                        'target_type': 'ip',
                                        'discovered_by': 'nmap',
                                        'is_primary': False
                                    }
                                )
                                
                                service_data = {
                                    'ip': ip,
                                    'port': port,
                                    'service': service,
                                    'protocol': port_protocol.split('/')[1] if '/' in port_protocol else 'tcp'
                                }
                                if version:
                                    service_data['version'] = version
                                if state:
                                    service_data['state'] = state
                                
                                ScanResult.objects.create(
                                    scan_session=self.scan_session,
                                    result_type='service',
                                    tool_name='nmap_service_detection',
                                    data=service_data,
                                    target=target,
                                    severity='info'
                                )
            
            # Handle array structure: [{ip, port, service, version}]
            elif isinstance(services_data, list):
                for service_entry in services_data:
                    if isinstance(service_entry, dict):
                        ip = service_entry.get('ip', '')
                        port = service_entry.get('port', '')
                        service = service_entry.get('service', '')
                        version = service_entry.get('version', '')
                        
                        if ip and port:
                            target, _ = Target.objects.get_or_create(
                                scan_session=self.scan_session,
                                value=ip,
                                defaults={
                                    'target_type': 'ip',
                                    'discovered_by': 'nmap',
                                    'is_primary': False
                                }
                            )
                            
                            service_data = {
                                'ip': ip,
                                'port': port,
                                'service': service
                            }
                            if version:
                                service_data['version'] = version
                            
                            ScanResult.objects.create(
                                scan_session=self.scan_session,
                                result_type='service',
                                tool_name='nmap_service_detection',
                                data=service_data,
                                target=target,
                                severity='info'
                            )
        
        elif os.path.exists(services_txt_file):
            # Fallback to text format
            with open(services_txt_file, 'r') as f:
                services = [line.strip() for line in f if line.strip()]
            
            for service_line in services:
                if ':' in service_line:
                    ip_port, service = service_line.split(':', 1)
                    if '/' in ip_port:
                        ip, port = ip_port.split('/', 1)
                        target, _ = Target.objects.get_or_create(
                            scan_session=self.scan_session,
                            value=ip,
                            defaults={
                                'target_type': 'ip',
                                'discovered_by': 'nmap',
                                'is_primary': False
                            }
                        )
                        
                        ScanResult.objects.create(
                            scan_session=self.scan_session,
                            result_type='service',
                            tool_name='nmap_service_detection',
                            data={'ip': ip, 'port': port, 'service': service.strip()},
                            target=target,
                            severity='info'
                        )
    
    def _process_web_enumeration(self, extract_path: str):
        """Process web enumeration results"""
        web_file = os.path.join(extract_path, 'web', 'all_urls.txt')
        
        if os.path.exists(web_file):
            with open(web_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            for url in urls:
                # Create URL target
                url_target, _ = Target.objects.get_or_create(
                    scan_session=self.scan_session,
                    value=url,
                    defaults={
                        'target_type': 'url',
                        'discovered_by': 'web_enumeration',
                        'is_primary': False
                    }
                )
                
                # Extract domain from URL
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc
                
                # Also create domain target
                domain_target, _ = Target.objects.get_or_create(
                    scan_session=self.scan_session,
                    value=domain,
                    defaults={
                        'target_type': 'domain',
                        'discovered_by': 'web_enumeration',
                        'is_primary': False
                    }
                )
                
                ScanResult.objects.create(
                    scan_session=self.scan_session,
                    result_type='reconnaissance',
                    tool_name='web_enumeration',
                    data={'url': url, 'domain': domain},
                    target=url_target,
                    severity='info'
                )
    
    def _process_vulnerabilities(self, extract_path: str):
        """Process vulnerability scan results"""
        vuln_file = os.path.join(extract_path, 'vuln_results.json')
        
        if os.path.exists(vuln_file):
            with open(vuln_file, 'r') as f:
                vuln_data = json.load(f)
            
            # Handle nested structure for Nuclei results
            if 'nuclei_results' in vuln_data:
                for target_url, target_data in vuln_data['nuclei_results'].items():
                    if 'vulnerabilities' in target_data:
                        for vuln in target_data['vulnerabilities']:
                            self._create_vulnerability_result(vuln, target_url)
            else:
                # Handle flat structure
                for vuln in vuln_data:
                    self._create_vulnerability_result(vuln)
    
    def _create_vulnerability_result(self, vuln_data: Dict[str, Any], target_url: Optional[str] = None):
        """Create a vulnerability result from vulnerability data"""
        # Extract target value
        if target_url:
            target_value = target_url
        elif 'host' in vuln_data:
            target_value = vuln_data['host']
        elif 'target' in vuln_data:
            target_value = vuln_data['target']
        else:
            return  # Skip if no target found
        
        # Extract severity
        severity = 'info'
        if 'info' in vuln_data and 'severity' in vuln_data['info']:
            severity = vuln_data['info']['severity'].lower()
        elif 'severity' in vuln_data:
            severity = vuln_data['severity'].lower()
        
        # Get or create target
        target, _ = Target.objects.get_or_create(
            scan_session=self.scan_session,
            value=target_value,
            defaults={
                'target_type': 'url' if target_value.startswith('http') else 'ip',
                'discovered_by': 'nuclei',
                'is_primary': False
            }
        )
        
        # Create vulnerability result
        ScanResult.objects.create(
            scan_session=self.scan_session,
            result_type='vulnerability',
            tool_name='nuclei',
            data=vuln_data,
            target=target,
            severity=severity
        )
    
    def _process_exploits(self, extract_path: str):
        """Process exploitation results"""
        # Try multiple possible paths
        exploit_files = [
            os.path.join(extract_path, 'exploit_results.json'),
            os.path.join(extract_path, 'exploit_results', 'successful_exploits.json')
        ]
        
        for exploit_file in exploit_files:
            if os.path.exists(exploit_file):
                with open(exploit_file, 'r') as f:
                    exploit_data = json.load(f)
                
                for exploit in exploit_data:
                    # Extract target value
                    target_value = exploit.get('host') or exploit.get('target', 'unknown')
                    
                    # Get or create target
                    target, _ = Target.objects.get_or_create(
                        scan_session=self.scan_session,
                        value=target_value,
                        defaults={
                            'target_type': 'url' if target_value.startswith('http') else 'ip',
                            'discovered_by': 'exploitation',
                            'is_primary': False
                        }
                    )
                    
                    # Create exploitation result
                    result = ScanResult.objects.create(
                        scan_session=self.scan_session,
                        result_type='exploitation',
                        tool_name=exploit.get('tool', 'unknown'),
                        data=exploit,
                        target=target,
                        severity=exploit.get('severity', 'high')
                    )
                    
                    # Create artifact for exploit script if referenced
                    if 'exploit_script_path' in exploit:
                        script_name = exploit['exploit_script_path'].split('/')[-1]
                        ScanArtifact.objects.create(
                            scan_session=self.scan_session,
                            result=result,
                            artifact_type='exploit_script',
                            name=script_name,
                            s3_key=f"admin_upload/{self.scan_session.id}/exploits/{script_name}",
                            file_size=0,  # We don't have the actual file size here
                            mime_type='text/x-python',
                            description=f"Exploit script for {exploit.get('vulnerability', 'unknown vulnerability')}"
                        )
                break  # Only process the first file found


def import_scan_from_zip_file(scan_session: ScanSession, zip_file_path: str) -> Dict[str, Any]:
    """
    Convenience function to import scan results from a ZIP file path.
    
    Args:
        scan_session: The ScanSession to populate
        zip_file_path: Path to the ZIP file
        
    Returns:
        Dict with import statistics
    """
    importer = ScanImporter(scan_session)
    return importer.import_from_zip_file(zip_file_path)


def import_scan_from_uploaded_file(scan_session: ScanSession, uploaded_file) -> Dict[str, Any]:
    """
    Convenience function to import scan results from an uploaded file.
    
    Args:
        scan_session: The ScanSession to populate
        uploaded_file: Django uploaded file object
        
    Returns:
        Dict with import statistics
    """
    importer = ScanImporter(scan_session)
    return importer.import_from_uploaded_file(uploaded_file)
