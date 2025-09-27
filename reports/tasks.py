import tempfile
import os
from celery import shared_task
from django.conf import settings
from django.utils import timezone
from .models import ScanSession
from .storage import ScanStorageManager
from .importers import import_scan_from_zip_file
import logging

logger = logging.getLogger(__name__)



@shared_task(bind=True)
def process_scan_archive(self, scan_session_id: str):
    """
    Process uploaded scan archive and extract results
    
    Args:
        scan_session_id: UUID of the ScanSession to process
    """
    try:
        # Get scan session
        scan_session = ScanSession.objects.get(id=scan_session_id)
        logger.info(f"Starting processing for scan session {scan_session_id}")
        
        # Update status to processing
        scan_session.status = 'processing'
        scan_session.started_at = timezone.now()
        scan_session.save()
        
        # Initialize storage manager
        storage_manager = ScanStorageManager(scan_session)
        
        # Download archive and process using unified import system
        with tempfile.TemporaryDirectory() as temp_dir:
            # Download archive from S3
            archive_content = storage_manager.get_file(scan_session.archive_s3_key)
            archive_path = os.path.join(temp_dir, 'archive.zip')
            
            with open(archive_path, 'wb') as f:
                f.write(archive_content)
            
            # Use unified import system
            try:
                stats = import_scan_from_zip_file(scan_session, archive_path)
                
                # Update scan session status
                scan_session.status = 'completed'
                scan_session.completed_at = timezone.now()
                scan_session.processing_log = f"Processing completed successfully: {stats}"
                scan_session.save()
                
                logger.info(f"Processing completed for scan session {scan_session_id}: {stats}")
                
            except Exception as e:
                logger.error(f"Error processing archive: {str(e)}")
                scan_session.status = 'failed'
                scan_session.error_message = str(e)
                scan_session.save()
                return
            
    except ScanSession.DoesNotExist:
        logger.error(f"Scan session {scan_session_id} not found")
        return
    except Exception as e:
        logger.error(f"Unexpected error processing scan {scan_session_id}: {str(e)}")
        
        # Update scan session with error
        try:
            scan_session = ScanSession.objects.get(id=scan_session_id)
            scan_session.status = 'failed'
            scan_session.error_message = str(e)
            scan_session.save()
        except:
            pass


def _store_raw_files(extract_path: str, storage_manager: ScanStorageManager):
    """Store raw files in organized S3 structure"""
    
    # Define file mappings
    file_mappings = {
        'enriched_summary_report.json': 'reports/enriched_summary_report.json',
        'vulnerability_summary_report.json': 'reports/vulnerability_summary_report.json',
        'exploitation_summary_report.json': 'reports/exploitation_summary_report.json',
        'enum_results.json': 'reports/enum_results.json',
        'vuln_results.json': 'reports/vuln_results.json',
        'exploit_results.json': 'reports/exploit_results.json',
    }
    
    # Store individual report files
    for filename, s3_path in file_mappings.items():
        file_path = os.path.join(extract_path, filename)
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                content = f.read()
            storage_manager.store_raw_output(content, 'reports', filename)
    
    # Store directory contents
    directories_to_store = [
        'raw_output',
        'exploits',
        'vulnerabilities',
        'services',
        'web',
        'ports',
        'domains',
        'ips',
        'emails'
    ]
    
    for directory in directories_to_store:
        dir_path = os.path.join(extract_path, directory)
        if os.path.exists(dir_path):
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, extract_path)
                    
                    with open(file_path, 'r') as f:
                        content = f.read()
                    
                    storage_manager.store_raw_output(
                        content, 
                        directory, 
                        relative_path.replace(f"{directory}/", "")
                    )


@shared_task
def cleanup_failed_scans():
    """Clean up failed scan sessions older than 7 days"""
    from django.utils import timezone
    from datetime import timedelta
    
    cutoff_date = timezone.now() - timedelta(days=7)
    failed_scans = ScanSession.objects.filter(
        status='failed',
        created_at__lt=cutoff_date
    )
    
    for scan in failed_scans:
        try:
            storage_manager = ScanStorageManager(scan)
            files = storage_manager.list_files()
            
            for file_info in files:
                storage_manager.delete_file(file_info['key'])
            
            scan.delete()
            logger.info(f"Cleaned up failed scan {scan.id}")
            
        except Exception as e:
            logger.error(f"Error cleaning up scan {scan.id}: {str(e)}")


@shared_task
def generate_scan_report(scan_session_id: str):
    """Generate comprehensive report for completed scan"""
    try:
        scan_session = ScanSession.objects.get(id=scan_session_id)
        
        if scan_session.status != 'completed':
            logger.warning(f"Cannot generate report for scan {scan_session_id} - status is {scan_session.status}")
            return
        
        # TODO: Implement report generation
        # This would create a comprehensive PDF/HTML report
        # combining all scan results, vulnerabilities, and recommendations
        
        logger.info(f"Report generation completed for scan {scan_session_id}")
        
    except ScanSession.DoesNotExist:
        logger.error(f"Scan session {scan_session_id} not found for report generation")
    except Exception as e:
        logger.error(f"Error generating report for scan {scan_session_id}: {str(e)}")
