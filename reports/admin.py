import os
from django.contrib import admin
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import path, reverse
from django.template.response import TemplateResponse
from .models import ScanSession, Target, ScanResult, ScanArtifact
from .admin_forms import ScanSessionAdminForm, ScanUploadForm


@admin.register(ScanSession)
class ScanSessionAdmin(admin.ModelAdmin):
    form = ScanSessionAdminForm
    list_display = ('id', 'organization', 'status', 'created_by', 'created_at', 'target_count', 'result_count')
    list_filter = ('status', 'organization', 'created_at')
    search_fields = ('description',)
    readonly_fields = ('id', 'created_at', 'duration', 'target_count', 'result_count')
    actions = ['import_scan_results_action', 'process_archives_now', 'reparse_scan_archives']
    
    fieldsets = (
        (None, {
            'fields': ('description', 'organization', 'created_by', 'status')
        }),
        ('File Storage', {
            'fields': ('archive_file',),
            'classes': ('collapse',)
        }),
        ('Timing', {
            'fields': ('started_at', 'completed_at', 'duration'),
            'classes': ('collapse',)
        }),
        ('Processing', {
            'fields': ('processing_log', 'error_message'),
            'classes': ('collapse',)
        }),
        ('Statistics', {
            'fields': ('target_count', 'result_count'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('metadata',),
            'classes': ('collapse',)
        }),
    )
    
    def target_count(self, obj):
        """Display target count"""
        if obj.pk:
            return obj.targets.count()
        return 0
    target_count.short_description = 'Targets'
    
    def result_count(self, obj):
        """Display result count"""
        if obj.pk:
            return obj.results.count()
        return 0
    result_count.short_description = 'Results'
    
    def get_urls(self):
        """Add custom URLs for bulk upload"""
        urls = super().get_urls()
        custom_urls = [
            path('bulk-upload/', self.admin_site.admin_view(self.bulk_upload_view), name='reports_scansession_bulk_upload'),
        ]
        return custom_urls + urls
    
    def bulk_upload_view(self, request):
        """Handle bulk upload of scan archives"""
        if request.method == 'POST':
            form = ScanUploadForm(request.POST, request.FILES)
            if form.is_valid():
                try:
                    # Create scan session
                    scan_session = ScanSession.objects.create(
                        name=form.cleaned_data['name'],
                        description=form.cleaned_data['description'],
                        organization=request.user.organization,
                        created_by=request.user,
                        status='uploaded'
                    )
                    
                    # Save the file to the FileField
                    archive_file = form.cleaned_data['archive']
                    scan_session.archive_file.save(
                        f"{form.cleaned_data['name'].replace(' ', '_')}.zip",
                        archive_file,
                        save=True
                    )
                    
                    # Process the uploaded archive using the admin form
                    admin_form = ScanSessionAdminForm()
                    admin_form._process_uploaded_archive(scan_session, archive_file)
                    
                    messages.success(request, f'Successfully uploaded and processed scan session: {scan_session.name}')
                    return redirect(f'admin:reports_scansession_change', scan_session.id)
                    
                except Exception as e:
                    messages.error(request, f'Error processing archive: {str(e)}')
        else:
            form = ScanUploadForm()
        
        context = {
            'form': form,
            'title': 'Bulk Upload Scan Results',
            'has_permission': True,
            'opts': self.model._meta,
        }
        return TemplateResponse(request, 'admin/reports/scansession/bulk_upload.html', context)
    
    def changelist_view(self, request, extra_context=None):
        """Add bulk upload link to changelist"""
        extra_context = extra_context or {}
        extra_context['bulk_upload_url'] = reverse('admin:reports_scansession_bulk_upload')
        return super().changelist_view(request, extra_context)
    
    def import_scan_results_action(self, request, queryset):
        """Admin action to show import instructions"""
        messages.info(
            request,
            "To import scan results, use the 'Bulk Upload Scan Results' button above or the management command:\n"
            "python manage.py import_scan_results <zip_file> --name 'Scan Name' --description 'Description'"
        )
    import_scan_results_action.short_description = "Show import instructions"
    
    def _calculate_checksum_from_file(self, file_obj):
        """Calculate SHA256 checksum from uploaded file object"""
        import hashlib
        file_obj.seek(0)
        return hashlib.sha256(file_obj.read()).hexdigest()
    
    def get_readonly_fields(self, request, obj=None):
        """Make archive_file readonly for existing objects"""
        readonly_fields = list(super().get_readonly_fields(request, obj))
        if obj and obj.pk:  # Existing object
            readonly_fields.append('archive_file')
        return readonly_fields

    def process_archives_now(self, request, queryset):
        """Admin action: process archives for selected scan sessions immediately."""
        from .admin_forms import ScanSessionAdminForm
        from .tasks import process_scan_archive
        processed = 0
        errors = 0
        for session in queryset:
            try:
                if session.archive_file:
                    # Process using admin form helper (local file)
                    form = ScanSessionAdminForm()
                    form._process_uploaded_archive(session, session.archive_file)
                    processed += 1
                else:
                    errors += 1
            except Exception as e:
                errors += 1
                self.message_user(request, f"Error processing {session.name}: {e}", level=messages.ERROR)
        if processed:
            self.message_user(request, f"Processed {processed} scan session(s).", level=messages.SUCCESS)
        if errors and not processed:
            self.message_user(request, "No archives found to process for selected session(s).", level=messages.WARNING)
    process_archives_now.short_description = "Process archives for selected sessions now"
    
    def reparse_scan_archives(self, request, queryset):
        """Admin action: reparse archives for selected scan sessions."""
        from django.core.management import call_command
        from io import StringIO
        import sys
        
        processed = 0
        errors = 0
        error_details = []
        
        for session in queryset:
            try:
                # Check if scan has archive file
                if not session.archive_file:
                    errors += 1
                    error_details.append(f"{session.id}: No archive file found")
                    continue
                
                # Check if archive file exists
                if not session.archive_file.path or not os.path.exists(session.archive_file.path):
                    errors += 1
                    error_details.append(f"{session.id}: Archive file not found on disk")
                    continue
                
                # Capture command output
                old_stdout = sys.stdout
                sys.stdout = captured_output = StringIO()
                
                try:
                    # Call the reparse command
                    call_command('reparse_scan', str(session.id), force=True)
                    processed += 1
                except Exception as e:
                    errors += 1
                    error_details.append(f"{session.id}: {str(e)}")
                finally:
                    sys.stdout = old_stdout
                    
            except Exception as e:
                errors += 1
                error_details.append(f"{session.id}: {str(e)}")
        
        # Show results
        if processed > 0:
            self.message_user(
                request, 
                f"Successfully reparsed {processed} scan session(s).", 
                level=messages.SUCCESS
            )
        
        if errors > 0:
            error_message = f"Failed to reparse {errors} scan session(s):\n" + "\n".join(error_details[:5])
            if len(error_details) > 5:
                error_message += f"\n... and {len(error_details) - 5} more errors"
            
            self.message_user(
                request, 
                error_message, 
                level=messages.ERROR
            )
        
        if processed == 0 and errors == 0:
            self.message_user(
                request, 
                "No valid scan sessions selected for reparsing.", 
                level=messages.WARNING
            )
    
    reparse_scan_archives.short_description = "Reparse archives for selected sessions"
    


@admin.register(Target)
class TargetAdmin(admin.ModelAdmin):
    list_display = ('value', 'target_type', 'scan_session', 'is_primary', 'is_alive', 'created_at')
    list_filter = ('target_type', 'is_primary', 'is_alive', 'scan_session__organization', 'created_at')
    search_fields = ('value', 'discovered_by')
    readonly_fields = ('id', 'created_at')
    
    fieldsets = (
        (None, {
            'fields': ('scan_session', 'target_type', 'value', 'parent_target')
        }),
        ('Discovery', {
            'fields': ('discovered_by', 'is_primary', 'is_alive', 'last_seen'),
        }),
        ('Metadata', {
            'fields': ('metadata',),
            'classes': ('collapse',)
        }),
    )


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ('tool_name', 'result_type', 'severity', 'target', 'scan_session', 'created_at')
    list_filter = ('result_type', 'tool_name', 'severity', 'status', 'scan_session__organization', 'created_at')
    search_fields = ('tool_name', 'data')
    readonly_fields = ('id', 'created_at', 'updated_at')
    
    fieldsets = (
        (None, {
            'fields': ('scan_session', 'result_type', 'target', 'tool_name', 'tool_version')
        }),
        ('Result Data', {
            'fields': ('data', 'severity', 'status'),
        }),
        ('File References', {
            'fields': ('raw_output_s3_key',),
            'classes': ('collapse',)
        }),
    )


@admin.register(ScanArtifact)
class ScanArtifactAdmin(admin.ModelAdmin):
    list_display = ('name', 'artifact_type', 'scan_session', 'file_size', 'created_at')
    list_filter = ('artifact_type', 'scan_session__organization', 'created_at')
    search_fields = ('name', 'description')
    readonly_fields = ('id', 'created_at')
    
    fieldsets = (
        (None, {
            'fields': ('scan_session', 'result', 'artifact_type', 'name', 'description')
        }),
        ('File Storage', {
            'fields': ('s3_key', 'file_size', 'mime_type'),
        }),
        ('Metadata', {
            'fields': ('metadata',),
            'classes': ('collapse',)
        }),
    )
