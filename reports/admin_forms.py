from django import forms
from django.core.exceptions import ValidationError
from .models import ScanSession, Target, ScanResult, ScanArtifact
from .importers import import_scan_from_uploaded_file
import logging

logger = logging.getLogger(__name__)


class ScanUploadForm(forms.Form):
    """Deprecated: retained for bulk upload view compatibility."""
    name = forms.CharField(max_length=255)
    description = forms.CharField(widget=forms.Textarea, required=False)
    archive = forms.FileField()

    def clean_archive(self):
        return self._validate_zip(self.cleaned_data.get('archive'))

    def _validate_zip(self, archive):
        if not archive:
            raise ValidationError("Archive file is required")
        if not archive.name.endswith('.zip'):
            raise ValidationError("Only ZIP files are supported")
        if archive.size > 100 * 1024 * 1024:
            raise ValidationError("Archive size cannot exceed 100MB")
        try:
            import zipfile
            with zipfile.ZipFile(archive, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                if not any('enriched_summary_report.json' in f or 'vulnerability_summary_report.json' in f for f in file_list):
                    raise ValidationError("Archive does not appear to contain valid scan results")
        except zipfile.BadZipFile:
            raise ValidationError("Invalid ZIP file")
        return archive


class ScanSessionAdminForm(forms.ModelForm):
    """Admin form that requires `archive_file` on create and processes it."""
    
    class Meta:
        model = ScanSession
        fields = '__all__'
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make archive_file required on create
        if not self.instance.pk:
            self.fields['archive_file'].required = True
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        
        if commit:
            instance.save()
            
            # Process uploaded archive if it exists
            if instance.archive_file:
                try:
                    self._process_uploaded_archive(instance, instance.archive_file)
                except ValidationError:
                    # _process_uploaded_archive already handles status and error_message
                    pass
        
        return instance
    
    def _process_uploaded_archive(self, scan_session, archive):
        """Process uploaded archive and populate models using unified import system"""
        try:
            # Use the unified import system
            stats = import_scan_from_uploaded_file(scan_session, archive)
            logger.info(f"Successfully processed uploaded archive for scan session {scan_session.id}: {stats}")
        except Exception as e:
            logger.error(f"Error processing uploaded archive: {str(e)}")
            raise ValidationError(f"Error processing archive: {str(e)}")
    
    def _calculate_checksum(self, file_path):
        """Calculate SHA256 checksum of file"""
        import hashlib
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    def _calculate_checksum_from_file(self, file_obj):
        """Calculate SHA256 checksum from uploaded file object"""
        import hashlib
        file_obj.seek(0)
        return hashlib.sha256(file_obj.read()).hexdigest()