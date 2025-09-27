import hashlib
import logging
from rest_framework import generics, permissions, status, viewsets
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from django.shortcuts import get_object_or_404, render
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.db.models import Count, Q
from django.core.serializers.json import DjangoJSONEncoder
import json
from .models import ScanSession, Target, ScanResult, ScanArtifact
from .serializers import (
    ScanSessionSerializer, ScanSessionListSerializer, ScanUploadSerializer,
    TargetSerializer, ScanResultSerializer, ScanArtifactSerializer
)

logger = logging.getLogger(__name__)


class ScanSessionViewSet(viewsets.ModelViewSet):
    """Clean, extensible API for scan sessions"""
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'created_by']
    search_fields = ['name', 'description']
    ordering_fields = ['created_at', 'started_at', 'completed_at']
    ordering = ['-created_at']

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return ScanSession.objects.all()
        return ScanSession.objects.filter(organization=user.organization)

    def get_serializer_class(self):
        if self.action == 'list':
            return ScanSessionListSerializer
        return ScanSessionSerializer

    def perform_create(self, serializer):
        user = self.request.user
        serializer.save(
            organization=user.organization,
            created_by=user
        )

    @action(detail=True, methods=['post'], parser_classes=[MultiPartParser, FormParser])
    def upload_archive(self, request, pk=None):
        """Upload scan archive and trigger processing"""
        scan_session = self.get_object()
        
        if scan_session.status != 'uploaded':
            return Response(
                {'error': 'Archive already uploaded for this scan session'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = ScanUploadSerializer(data=request.data)
        if serializer.is_valid():
            archive_file = serializer.validated_data['archive']
            
            # Calculate checksum
            archive_file.seek(0)
            file_content = archive_file.read()
            checksum = hashlib.sha256(file_content).hexdigest()
            
            # Update scan session with archive info
            scan_session.archive_size = len(file_content)
            scan_session.archive_checksum = checksum
            scan_session.archive_s3_key = f"scans/{scan_session.id}/archive.zip"
            scan_session.status = 'processing'
            scan_session.save()
            
            # Upload to S3 and trigger processing
            from .storage import ScanStorageManager
            from .tasks import process_scan_archive
            
            storage_manager = ScanStorageManager(scan_session)
            archive_file.seek(0)
            storage_manager.store_archive(archive_file)
            
            # Trigger async processing
            process_scan_archive.delay(str(scan_session.id))
            
            logger.info(f"Archive uploaded and processing started for scan session {scan_session.id}")
            
            return Response({
                'message': 'Archive uploaded successfully and processing started',
                'scan_session_id': str(scan_session.id),
                'status': scan_session.status
            })
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['get'])
    def results_by_type(self, request, pk=None):
        """Get results filtered by type"""
        scan_session = self.get_object()
        result_type = request.query_params.get('type')
        
        results = scan_session.results.all()
        if result_type:
            results = results.filter(result_type=result_type)
        
        serializer = ScanResultSerializer(results, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def results_by_target(self, request, pk=None):
        """Get results filtered by target"""
        scan_session = self.get_object()
        target_id = request.query_params.get('target_id')
        
        results = scan_session.results.all()
        if target_id:
            results = results.filter(target_id=target_id)
        
        serializer = ScanResultSerializer(results, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def targets(self, request, pk=None):
        """Get all targets for this scan session"""
        scan_session = self.get_object()
        targets = scan_session.targets.all()
        serializer = TargetSerializer(targets, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def artifacts(self, request, pk=None):
        """Get all artifacts for this scan session"""
        scan_session = self.get_object()
        artifacts = scan_session.artifacts.all()
        serializer = ScanArtifactSerializer(artifacts, many=True)
        return Response(serializer.data)


class TargetViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only API for targets"""
    serializer_class = TargetSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['target_type', 'is_primary', 'is_alive']
    search_fields = ['value']

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return Target.objects.all()
        return Target.objects.filter(scan_session__organization=user.organization)

    @action(detail=True, methods=['get'])
    def results(self, request, pk=None):
        """Get all results for this target"""
        target = self.get_object()
        results = target.results.all()
        serializer = ScanResultSerializer(results, many=True)
        return Response(serializer.data)


class ScanResultViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only API for scan results"""
    serializer_class = ScanResultSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['result_type', 'tool_name', 'severity', 'status']
    search_fields = ['tool_name', 'data']
    ordering_fields = ['created_at', 'severity']
    ordering = ['-created_at']

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return ScanResult.objects.all()
        return ScanResult.objects.filter(scan_session__organization=user.organization)


class ScanArtifactViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only API for scan artifacts"""
    serializer_class = ScanArtifactSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['artifact_type']
    search_fields = ['name', 'description']

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return ScanArtifact.objects.all()
        return ScanArtifact.objects.filter(scan_session__organization=user.organization)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def scan_statistics(request):
    """Get statistics for the user's organization scans"""
    user = request.user
    if user.is_superuser:
        scans = ScanSession.objects.all()
    else:
        scans = ScanSession.objects.filter(organization=user.organization)

    stats = {
        'total_scans': scans.count(),
        'scans_by_status': {},
        'results_by_type': {},
        'results_by_severity': {},
        'recent_scans': ScanSessionListSerializer(
            scans.order_by('-created_at')[:5], many=True
        ).data
    }

    # Count by status
    for status_choice, _ in ScanSession._meta.get_field('status').choices:
        stats['scans_by_status'][status_choice] = scans.filter(status=status_choice).count()

    # Count results by type
    results = ScanResult.objects.filter(scan_session__in=scans)
    for result_type, _ in ScanResult.RESULT_TYPES:
        stats['results_by_type'][result_type] = results.filter(result_type=result_type).count()

    # Count results by severity
    for severity, _ in ScanResult._meta.get_field('severity').choices:
        stats['results_by_severity'][severity] = results.filter(severity=severity).count()

    return Response(stats)


# Django template views for scan management
@login_required(login_url='/accounts/login/')
def dashboard(request):
    """
    Serve the main dashboard.
    """
    # Get the last 12 scans for the user's organization
    last_12_scans = ScanSession.objects.filter(
        organization=request.user.organization
    ).order_by('-created_at')[:12]
    
    # Prepare chart data for attack surface history
    chart_data = []
    vulnerability_chart_data = []
    for scan in last_12_scans:
        target_count = scan.targets.count()
        vulnerability_count = ScanResult.objects.filter(
            scan_session=scan, 
            result_type='vulnerability'
        ).count()
        
        chart_data.append({
            'scan_id': str(scan.id),
            'description': scan.description,
            'created_at': scan.created_at.strftime('%Y-%m-%d'),
            'target_count': target_count,
            'status': scan.status
        })
        
        vulnerability_chart_data.append({
            'scan_id': str(scan.id),
            'description': scan.description,
            'created_at': scan.created_at.strftime('%Y-%m-%d'),
            'vulnerability_count': vulnerability_count,
            'status': scan.status
        })
    
    # Reverse to show oldest first
    chart_data.reverse()
    vulnerability_chart_data.reverse()
    
    context = {
        'debug': settings.DEBUG,
        'user': request.user,
        'chart_data': json.dumps(chart_data, cls=DjangoJSONEncoder),
        'vulnerability_chart_data': json.dumps(vulnerability_chart_data, cls=DjangoJSONEncoder),
    }

    return render(request, 'reports/dashboard.html', context)


@login_required(login_url='/accounts/login/')
def scans(request):
    """
    List all scans for the user's organization.
    """
    # Get scans with annotations for counts
    scans = ScanSession.objects.filter(
        organization=request.user.organization
    ).order_by('-created_at')
    
    context = {
        'scans': scans,
        'user': request.user,
    }
    
    return render(request, 'reports/scans.html', context)


@login_required(login_url='/accounts/login/')
def scan_detail(request, scan_id):
    """
    Show detailed information about a specific scan.
    """
    scan = get_object_or_404(ScanSession, id=scan_id, organization=request.user.organization)
    
    # Get filter parameters
    result_type = request.GET.get('type', 'all')
    severity = request.GET.get('severity', 'all')
    page = int(request.GET.get('page', 1))
    active_tab = request.GET.get('tab', 'targets')
    per_page = 50
    
    # Get all results for this scan
    all_results = scan.results.all().order_by('-created_at')
    
    # Apply filters
    filtered_results = all_results
    if result_type != 'all':
        filtered_results = filtered_results.filter(result_type=result_type)
    if severity != 'all':
        filtered_results = filtered_results.filter(severity=severity)
    
    # Calculate pagination
    total_results = filtered_results.count()
    total_pages = (total_results + per_page - 1) // per_page  # Ceiling division
    start = (page - 1) * per_page
    end = start + per_page
    paginated_results = filtered_results[start:end]
    
    # Calculate display indices
    start_index = start
    end_index = min(end, total_results)
    
    # Create page range for pagination
    page_range = range(1, total_pages + 1)
    
    # Get targets for this scan
    targets = scan.targets.all().order_by('value')
    
    # Get services separately
    services = all_results.filter(result_type='service')
    
    # Get vulnerabilities separately  
    vulnerabilities = all_results.filter(result_type='vulnerability')
    
    # Calculate vulnerability count for this scan
    vulnerability_count = vulnerabilities.count()
    
    context = {
        'scan': scan,
        'all_results': all_results,
        'filtered_results': paginated_results,
        'total_results': total_results,
        'current_page': page,
        'total_pages': total_pages,
        'page_range': page_range,
        'per_page': per_page,
        'start_index': start_index,
        'end_index': end_index,
        'current_type': result_type,
        'current_severity': severity,
        'active_tab': active_tab,
        'targets': targets,
        'services': services,
        'vulnerabilities': vulnerabilities,
        'vulnerability_count': vulnerability_count,
        'user': request.user,
    }
    
    return render(request, 'reports/scan_detail.html', context)


@login_required(login_url='/accounts/login/')
def target_detail(request, scan_id, target_id):
    """
    Show detailed information about a specific target.
    """
    scan = get_object_or_404(ScanSession, id=scan_id, organization=request.user.organization)
    target = get_object_or_404(Target, id=target_id, scan_session=scan)
    
    # Get all results for this target
    all_results = target.results.all().order_by('-created_at')
    
    # Get services for this target
    services = all_results.filter(result_type='service')
    
    # Get vulnerabilities for this target
    vulnerabilities = all_results.filter(result_type='vulnerability')
    
    context = {
        'scan': scan,
        'target': target,
        'all_results': all_results,
        'services': services,
        'vulnerabilities': vulnerabilities,
        'user': request.user,
    }
    
    # Check if this is a partial request (for drawer)
    if request.headers.get('X-Partial'):
        return render(request, 'reports/partials/target_detail_drawer.html', context)
    else:
        return render(request, 'reports/target_detail_full.html', context)


@login_required(login_url='/accounts/login/')
def result_detail(request, scan_id, result_id):
    """
    Show detailed information about a specific result.
    """
    scan = get_object_or_404(ScanSession, id=scan_id, organization=request.user.organization)
    result = get_object_or_404(ScanResult, id=result_id, scan_session=scan)
    
    context = {
        'scan': scan,
        'result': result,
        'user': request.user,
    }
    
    # Check if this is a partial request (for modal)
    if request.headers.get('X-Partial'):
        return render(request, 'reports/partials/result_detail_modal.html', context)
    else:
        return render(request, 'reports/result_detail_full.html', context)


@login_required(login_url='/accounts/login/')
def debug_scans_data(request):
    """
    Debug view to inspect scan data.
    """
    if not request.user.is_superuser:
        return render(request, '403.html', status=403)
    
    scans = ScanSession.objects.filter(organization=request.user.organization)
    
    debug_data = []
    for scan in scans:
        targets = scan.targets.all()
        results = scan.results.all()
        
        debug_data.append({
            'scan': scan,
            'targets': list(targets.values('id', 'value', 'target_type')),
            'results': list(results.values('id', 'result_type', 'tool_name', 'severity')),
            'target_count': targets.count(),
            'result_count': results.count(),
        })
    
    context = {
        'debug_data': debug_data,
        'user': request.user,
    }
    
    return render(request, 'reports/debug_scans.html', context)
