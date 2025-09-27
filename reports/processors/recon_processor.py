import json
import os
from typing import Dict, Any, List
from .base import BaseScanProcessor
from ..models import Target, ScanResult


class ReconnaissanceProcessor(BaseScanProcessor):
    """Process reconnaissance results"""
    
    def process(self) -> bool:
        """Process reconnaissance data from scan archive"""
        try:
            self.logger.info("Starting reconnaissance processing")
            
            # Parse enriched_summary_report.json
            summary_data = self._parse_summary_report()
            if summary_data:
                self._process_summary_data(summary_data)
            
            # Parse individual result files
            self._process_domains()
            self._process_ips()
            self._process_ports()
            self._process_services()
            self._process_web_enumeration()
            
            self.logger.info("Reconnaissance processing completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error processing reconnaissance: {str(e)}")
            self.update_scan_status('failed', str(e))
            return False
    
    def _parse_summary_report(self) -> Dict[str, Any]:
        """Parse the enriched summary report"""
        # TODO: Implement actual file parsing from S3
        # For now, return sample data structure
        return {
            "report_type": "ENRICHED RECONNAISSANCE & ENUMERATION SUMMARY REPORT",
            "input_targets": {
                "count": 3,
                "targets": ["34.243.167.33", "keepsimple.dev", "www.keepsimple.dev"]
            },
            "enumeration_results": {
                "targets_with_open_ports": 1,
                "targets_with_services_detected": 1,
                "web_services_enumerated": 6
            }
        }
    
    def _process_summary_data(self, summary_data: Dict[str, Any]):
        """Process summary data and create targets"""
        input_targets = summary_data.get('input_targets', {}).get('targets', [])
        
        for target_value in input_targets:
            # Determine target type
            if target_value.replace('.', '').isdigit():
                target_type = 'ip'
            elif target_value.startswith(('http://', 'https://')):
                target_type = 'url'
            else:
                target_type = 'domain'
            
            # Create primary target
            target = self.create_target(
                value=target_value,
                target_type=target_type,
                is_primary=True
            )
            
            # Create result for this target
            self.create_result(
                result_type='reconnaissance',
                tool_name='summary',
                data=summary_data,
                target=target,
                severity='info'
            )
    
    def _process_domains(self):
        """Process discovered domains"""
        # TODO: Parse domains/all_domains.txt from S3
        domains = ['keepsimple.dev', 'www.keepsimple.dev']
        
        for domain in domains:
            target = self.create_target(
                value=domain,
                target_type='domain',
                discovered_by='subfinder'
            )
            
            self.create_result(
                result_type='reconnaissance',
                tool_name='subfinder',
                data={'domain': domain, 'discovery_method': 'subdomain_enumeration'},
                target=target,
                severity='info'
            )
    
    def _process_ips(self):
        """Process discovered IP addresses"""
        # TODO: Parse ips/all_ips.txt from S3
        ips = ['34.243.167.33']
        
        for ip in ips:
            target = self.create_target(
                value=ip,
                target_type='ip',
                discovered_by='dns_resolution'
            )
            
            self.create_result(
                result_type='reconnaissance',
                tool_name='dns_resolver',
                data={'ip': ip, 'discovery_method': 'dns_resolution'},
                target=target,
                severity='info'
            )
    
    def _process_ports(self):
        """Process port scanning results"""
        # TODO: Parse ports/open_ports.json from S3
        port_data = {
            "34.243.167.33": {
                "22/tcp": {"service": "ssh", "state": "open"},
                "80/tcp": {"service": "http", "state": "open"},
                "443/tcp": {"service": "https", "state": "open"}
            }
        }
        
        for ip, ports in port_data.items():
            ip_target = Target.objects.filter(
                scan_session=self.scan_session,
                value=ip,
                target_type='ip'
            ).first()
            
            if ip_target:
                self.create_result(
                    result_type='reconnaissance',
                    tool_name='nmap',
                    data={'ip': ip, 'open_ports': ports},
                    target=ip_target,
                    severity='info'
                )
    
    def _process_services(self):
        """Process service detection results"""
        # TODO: Parse services/detected_services.json from S3
        service_data = {
            "34.243.167.33": {
                "22/tcp": {
                    "service": "ssh",
                    "version": "OpenSSH 8.9p1 Ubuntu 3ubuntu0.13"
                },
                "80/tcp": {
                    "service": "http",
                    "version": "nginx 1.18.0 (Ubuntu)"
                }
            }
        }
        
        for ip, services in service_data.items():
            ip_target = Target.objects.filter(
                scan_session=self.scan_session,
                value=ip,
                target_type='ip'
            ).first()
            
            if ip_target:
                self.create_result(
                    result_type='reconnaissance',
                    tool_name='nmap_service_detection',
                    data={'ip': ip, 'services': services},
                    target=ip_target,
                    severity='info'
                )
    
    def _process_web_enumeration(self):
        """Process web enumeration results"""
        # TODO: Parse web/web_enumeration.json from S3
        web_data = {
            "https://keepsimple.dev": {
                "directories": ["admin", "robots.txt", "sitemap.xml"],
                "technology": {
                    "server": "nginx/1.18.0 (Ubuntu)",
                    "status_code": 200
                }
            }
        }
        
        for url, data in web_data.items():
            url_target = self.create_target(
                value=url,
                target_type='url',
                discovered_by='web_enumeration'
            )
            
            self.create_result(
                result_type='reconnaissance',
                tool_name='gobuster',
                data={'url': url, 'enumeration_data': data},
                target=url_target,
                severity='info'
            )
