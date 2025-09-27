from django.apps import AppConfig


class ReportsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'reports'

    def ready(self):
        # Import signals to ensure post_save hooks are registered
        from . import signals  # noqa: F401
