from rest_framework import serializers
from .models import Organization


class OrganizationSerializer(serializers.ModelSerializer):
    user_count = serializers.IntegerField(read_only=True)
    admin_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Organization
        fields = [
            'id', 'name', 'description', 'website', 'contact_email',
            'user_count', 'admin_count', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'user_count', 'admin_count']
