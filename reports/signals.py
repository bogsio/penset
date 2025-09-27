from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import ScanSession


@receiver(post_save, sender=ScanSession)
def process_archive_on_create(sender, instance: ScanSession, created: bool, **kwargs):
    """Ensure archives are processed regardless of creation path.

    - On create: if an `archive_file` is attached, process it immediately.
    - On update: if data still empty and a file exists with status 'uploaded', process as fallback.
    """
    try:
        should_process = False
        if created and instance.archive_file:
            should_process = True
        elif instance.archive_file and instance.status == 'uploaded' and instance.results.count() == 0:
            should_process = True

        if should_process:
            # Reuse the admin form helper to keep a single processing implementation
            from .admin_forms import ScanSessionAdminForm
            form = ScanSessionAdminForm()
            form._process_uploaded_archive(instance, instance.archive_file)
    except Exception:
        # Let normal error reporting via admin form or tasks handle details
        # We avoid raising to not break save flows outside admin/API
        pass


