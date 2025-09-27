import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from ..models import ScanSession, Target, ScanResult, ScanArtifact


class BaseScanProcessor(ABC):
    """Base class for all scan processors - easily extensible"""
    
    def __init__(self, scan_session: ScanSession):
        self.scan_session = scan_session
        self.logger = logging.getLogger(f"scan_processor_{scan_session.id}")
    
    @abstractmethod
    def process(self) -> bool:
        """Main processing method - override in subclasses"""
        pass
    
    def create_target(self, value: str, target_type: str, **kwargs) -> Target:
        """Helper to create targets consistently"""
        target, created = Target.objects.get_or_create(
            scan_session=self.scan_session,
            value=value,
            defaults={
                'target_type': target_type,
                **kwargs
            }
        )
        if created:
            self.logger.info(f"Created target: {value} ({target_type})")
        return target
    
    def create_result(self, result_type: str, tool_name: str, data: Dict[str, Any], 
                     target: Optional[Target] = None, **kwargs) -> ScanResult:
        """Helper to create results consistently"""
        result = ScanResult.objects.create(
            scan_session=self.scan_session,
            result_type=result_type,
            tool_name=tool_name,
            data=data,
            target=target,
            **kwargs
        )
        self.logger.info(f"Created result: {tool_name} - {result_type}")
        return result
    
    def create_artifact(self, artifact_type: str, name: str, s3_key: str, 
                       file_size: int, result: Optional[ScanResult] = None, 
                       **kwargs) -> ScanArtifact:
        """Helper to create artifacts consistently"""
        artifact = ScanArtifact.objects.create(
            scan_session=self.scan_session,
            result=result,
            artifact_type=artifact_type,
            name=name,
            s3_key=s3_key,
            file_size=file_size,
            **kwargs
        )
        self.logger.info(f"Created artifact: {name} ({artifact_type})")
        return artifact
    
    def update_scan_status(self, status: str, error_message: str = None):
        """Update scan session status"""
        self.scan_session.status = status
        if error_message:
            self.scan_session.error_message = error_message
        self.scan_session.save()
        self.logger.info(f"Updated scan status to: {status}")


class ScanProcessorRegistry:
    """Registry for scan processors - extensible"""
    
    _processors = {}
    
    @classmethod
    def register(cls, processor_type: str, processor_class):
        """Register a new processor type"""
        cls._processors[processor_type] = processor_class
    
    @classmethod
    def get_processor(cls, processor_type: str, scan_session: ScanSession) -> BaseScanProcessor:
        """Get a processor instance"""
        if processor_type not in cls._processors:
            raise ValueError(f"Unknown processor type: {processor_type}")
        
        processor_class = cls._processors[processor_type]
        return processor_class(scan_session)
    
    @classmethod
    def list_processors(cls):
        """List all registered processors"""
        return list(cls._processors.keys())
