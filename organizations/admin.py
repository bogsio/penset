from django.contrib import admin
from .models import Organization


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('name', 'contact_email', 'user_count', 'admin_count', 'is_active', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'description', 'contact_email')
    readonly_fields = ('created_at', 'updated_at', 'user_count', 'admin_count')
    
    fieldsets = (
        (None, {
            'fields': ('name', 'description', 'website', 'contact_email', 'is_active')
        }),
        ('Statistics', {
            'fields': ('user_count', 'admin_count'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
