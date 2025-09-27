import uuid
from django.db import models
from django.contrib.auth import get_user_model
from organizations.models import Organization

User = get_user_model()


class ScanSession(models.Model):
    """Main container for a complete penetration test session"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='scan_sessions')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_scans')
    
    # Basic info
    description = models.TextField(blank=True)
    
    # Status tracking
    status = models.CharField(max_length=20, choices=[
        ('uploaded', 'Archive Uploaded'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed')
    ], default='uploaded')
    
    # File storage
    archive_file = models.FileField(
        upload_to='scans/archives/',
        help_text="ZIP file containing scan results",
        default=""
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Processing metadata
    processing_log = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    
    # Extensible metadata
    metadata = models.JSONField(default=dict, blank=True, null=True)
    
    class Meta:
        ordering = ['-created_at']
        db_table = 'scan_sessions'

    def __str__(self):
        return f"Session {self.id} ({self.status})"

    @property
    def target_count(self):
        return self.targets.count()

    @property
    def issue_count(self):
        return self.results.count()

    @property
    def duration(self):
        """Calculate the duration of the scan"""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None
    
    @property
    def archive_url(self):
        """Get the URL for the archive file"""
        if self.archive_file:
            return self.archive_file.url
        return None
    
    @property
    def archive_name(self):
        """Get the filename of the archive"""
        if self.archive_file:
            return self.archive_file.name
        return None
    
    def get_archive_file(self):
        """Get the archive file for processing"""
        if self.archive_file:
            return self.archive_file
        return None
    
    def calculate_checksum(self):
        """Calculate SHA256 checksum of the archive file"""
        import hashlib
        if self.archive_file:
            self.archive_file.seek(0)
            return hashlib.sha256(self.archive_file.read()).hexdigest()
        return None


class Target(models.Model):
    """Individual targets within a scan session - highly extensible"""
    TARGET_TYPES = [
        ('domain', 'Domain'),
        ('ip', 'IP Address'),
        ('url', 'URL'),
        ('subdomain', 'Subdomain'),
        ('email', 'Email Address'),
        ('port', 'Port'),
        ('service', 'Service'),
        ('file', 'File Path'),
        ('endpoint', 'API Endpoint'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='targets')
    
    # Target identification
    target_type = models.CharField(max_length=20, choices=TARGET_TYPES)
    value = models.CharField(max_length=500)
    
    # Relationships
    parent_target = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='child_targets')
    
    # Discovery metadata
    discovered_by = models.CharField(max_length=100, blank=True)
    is_primary = models.BooleanField(default=False)
    is_alive = models.BooleanField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    
    # Extensible metadata
    metadata = models.JSONField(default=dict, blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['scan_session', 'value']
        indexes = [
            models.Index(fields=['scan_session', 'target_type']),
            models.Index(fields=['scan_session', 'is_primary']),
            models.Index(fields=['parent_target']),
        ]
        db_table = 'targets'

    def __str__(self):
        return f"{self.value} ({self.target_type})"


class ScanResult(models.Model):
    """Generic scan result container - extensible for any scan type"""
    RESULT_TYPES = [
        ('reconnaissance', 'Reconnaissance'),
        ('service', 'Service Detection'),
        ('vulnerability', 'Vulnerability'),
        ('exploitation', 'Exploitation'),
        ('post_exploitation', 'Post-Exploitation'),
        ('custom', 'Custom'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='results')
    result_type = models.CharField(max_length=30, choices=RESULT_TYPES)
    
    # Target relationship
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='results', null=True, blank=True)
    
    # Tool information
    tool_name = models.CharField(max_length=100)
    tool_version = models.CharField(max_length=50, blank=True)
    
    # Result data
    data = models.JSONField(default=dict)
    
    # Severity/priority
    severity = models.CharField(max_length=20, choices=[
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ], blank=True)
    
    # Status tracking
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ], default='completed')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Raw file references
    raw_output_s3_key = models.CharField(max_length=500, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['scan_session', 'result_type']),
            models.Index(fields=['scan_session', 'tool_name']),
            models.Index(fields=['scan_session', 'severity']),
            models.Index(fields=['target', 'result_type']),
        ]
        db_table = 'scan_results'

    def __str__(self):
        return f"{self.tool_name} - {self.result_type} ({self.severity})"


class ScanArtifact(models.Model):
    """Store generated artifacts (exploits, reports, etc.) - extensible"""
    ARTIFACT_TYPES = [
        ('exploit_script', 'Exploit Script'),
        ('report', 'Report'),
        ('screenshot', 'Screenshot'),
        ('log_file', 'Log File'),
        ('config_file', 'Configuration File'),
        ('custom', 'Custom'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='artifacts')
    result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='artifacts', null=True, blank=True)
    
    artifact_type = models.CharField(max_length=30, choices=ARTIFACT_TYPES)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    
    # File storage
    s3_key = models.CharField(max_length=500)
    file_size = models.BigIntegerField()
    mime_type = models.CharField(max_length=100, blank=True)
    
    # Metadata
    metadata = models.JSONField(default=dict, blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        db_table = 'scan_artifacts'

    def __str__(self):
        return f"{self.name} ({self.artifact_type})"
