from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'reports'

# Create router for ViewSets
router = DefaultRouter()
router.register(r'scans', views.ScanSessionViewSet, basename='scansession')
router.register(r'targets', views.TargetViewSet, basename='target')
router.register(r'results', views.ScanResultViewSet, basename='scanresult')
router.register(r'artifacts', views.ScanArtifactViewSet, basename='scanartifact')

urlpatterns = [
    # API routes
    path('api/', include(router.urls)),
    path('api/statistics/', views.scan_statistics, name='scan_statistics'),
    
    # Django template views
    path('', views.dashboard, name='dashboard'),
    path('scans/', views.scans, name='scans'),
    path('scans/<uuid:scan_id>/', views.scan_detail, name='scan_detail'),
    path('scans/<uuid:scan_id>/targets/<uuid:target_id>/', views.target_detail, name='target_detail'),
    path('scans/<uuid:scan_id>/results/<uuid:result_id>/', views.result_detail, name='result_detail'),
    path('debug/scans-data/', views.debug_scans_data, name='debug_scans_data'),
]
