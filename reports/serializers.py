from rest_framework import serializers
from .models import ScanSession, Target, ScanResult, ScanArtifact
from accounts.serializers import UserSerializer


class TargetSerializer(serializers.ModelSerializer):
    child_targets = serializers.SerializerMethodField()
    
    class Meta:
        model = Target
        fields = [
            'id', 'target_type', 'value', 'parent_target', 'discovered_by',
            'is_primary', 'is_alive', 'last_seen', 'metadata', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']
    
    def get_child_targets(self, obj):
        return TargetSerializer(obj.child_targets.all(), many=True).data


class ScanArtifactSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanArtifact
        fields = [
            'id', 'artifact_type', 'name', 'description', 's3_key',
            'file_size', 'mime_type', 'metadata', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class ScanResultSerializer(serializers.ModelSerializer):
    target = TargetSerializer(read_only=True)
    artifacts = ScanArtifactSerializer(many=True, read_only=True)
    
    class Meta:
        model = ScanResult
        fields = [
            'id', 'result_type', 'target', 'tool_name', 'tool_version',
            'data', 'severity', 'status', 'raw_output_s3_key', 'artifacts',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class ScanSessionSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.full_name', read_only=True)
    duration = serializers.ReadOnlyField()
    targets = TargetSerializer(many=True, read_only=True)
    results = ScanResultSerializer(many=True, read_only=True)
    artifacts = ScanArtifactSerializer(many=True, read_only=True)
    
    class Meta:
        model = ScanSession
        fields = [
            'id', 'description', 'status', 'organization', 'organization_name',
            'created_by', 'created_by_name', 'processing_log', 'error_message', 'metadata',
            'duration', 'targets', 'results', 'artifacts',
            'created_at', 'started_at', 'completed_at'
        ]
        read_only_fields = [
            'id', 'created_at', 'duration', 'targets', 'results', 'artifacts'
        ]


class ScanSessionListSerializer(serializers.ModelSerializer):
    """Simplified serializer for list views"""
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.full_name', read_only=True)
    duration = serializers.ReadOnlyField()
    target_count = serializers.SerializerMethodField()
    result_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ScanSession
        fields = [
            'id', 'description', 'status', 'organization_name',
            'created_by_name', 'duration', 'target_count', 'result_count',
            'created_at', 'started_at', 'completed_at'
        ]
    
    def get_target_count(self, obj):
        return obj.targets.count()
    
    def get_result_count(self, obj):
        return obj.results.count()


class ScanUploadSerializer(serializers.Serializer):
    """Serializer for scan archive upload"""
    archive = serializers.FileField()
    description = serializers.CharField(required=False, allow_blank=True)
    
    def validate_archive(self, value):
        """Validate uploaded archive"""
        if not value.name.endswith(('.zip', '.tar.gz', '.tar')):
            raise serializers.ValidationError("Only ZIP and TAR archives are supported")
        
        if value.size > 100 * 1024 * 1024:  # 100MB limit
            raise serializers.ValidationError("Archive size cannot exceed 100MB")
        
        return value
