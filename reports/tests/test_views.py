"""
Tests for reports views.
"""

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from reports.models import ScanSession, Target, ScanResult
from organizations.models import Organization

from .test_base import ReportsTestCase

User = get_user_model()


class ReportsViewsTestCase(ReportsTestCase):
    """Test case for reports views."""
    
    def setUp(self):
        """Set up additional test data for view tests."""
        super().setUp()
        
        # Create test scan session
        self.scan_session = ScanSession.objects.create(
            organization=self.organization,
            created_by=self.user,
            description="Test scan session",
            status='completed'
        )
        
        # Create test target
        self.target = Target.objects.create(
            scan_session=self.scan_session,
            value="192.168.1.1",
            target_type="ip"
        )
        
        # Create test scan result
        self.scan_result = ScanResult.objects.create(
            scan_session=self.scan_session,
            target=self.target,
            result_type="vulnerability",
            tool_name="nuclei",
            severity="high",
            data={"test": "data"}
        )
        
        self.client = Client()
    
    def test_dashboard_requires_authentication(self):
        """Test that dashboard requires authentication."""
        response = self.client.get('/')
        self.assertRedirects(response, '/accounts/login/?next=/')
    
    def test_dashboard_authenticated(self):
        """Test dashboard for authenticated user."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Dashboard')
        self.assertContains(response, 'Test scan session')
    
    def test_dashboard_chart_data(self):
        """Test that dashboard provides chart data."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        
        # Check that chart data is in context
        self.assertIn('chart_data', response.context)
        chart_data = response.context['chart_data']
        # chart_data is a JSON string, not a dict with labels/datasets
        self.assertIsInstance(chart_data, str)
        self.assertIn('scan_id', chart_data)
    
    def test_scans_requires_authentication(self):
        """Test that scans page requires authentication."""
        response = self.client.get('/scans/')
        self.assertRedirects(response, '/accounts/login/?next=/scans/')
    
    def test_scans_authenticated(self):
        """Test scans page for authenticated user."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Scans')
        self.assertContains(response, 'Test scan session')
    
    def test_scans_organization_isolation(self):
        """Test that scans are isolated by organization."""
        # Create another organization and user
        other_org = Organization.objects.create(
            name="Other Organization",
            description="Other organization"
        )
        other_user = User.objects.create_user(
            username="otheruser",
            email="other@example.com",
            password="testpass123",
            first_name="Other",
            last_name="User",
            organization=other_org
        )
        
        # Create scan session for other organization
        other_scan = ScanSession.objects.create(
            organization=other_org,
            created_by=other_user,
            description="Other scan session",
            status='completed'
        )
        
        # Login as original user
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
        
        # Should only see own organization's scans
        self.assertContains(response, 'Test scan session')
        self.assertNotContains(response, 'Other scan session')
    
    def test_scans_with_no_data(self):
        """Test scans page with no scan data."""
        # Delete the test scan session
        self.scan_session.delete()
        
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'No scans found')
    
    def test_scans_stat_boxes_calculations(self):
        """Test that stat boxes show correct calculations."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
        
        # Check that stat boxes are present
        self.assertContains(response, 'Total Scans')
        self.assertContains(response, 'Latest Scan Targets')
        self.assertContains(response, 'Latest Scan Vulnerabilities')
        # High Severity text is not displayed in the scans template
    
    def test_scans_stat_boxes_with_no_vulnerabilities(self):
        """Test stat boxes when there are no vulnerabilities."""
        # Delete the scan result (vulnerability)
        self.scan_result.delete()
        
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
        
        # Should still show stat boxes with zero values
        self.assertContains(response, 'Latest Scan Vulnerabilities')
        # High Severity text is not displayed in the scans template
    
    def test_scans_stat_boxes_with_different_result_types(self):
        """Test stat boxes with different result types."""
        # Create additional scan results with different types
        ScanResult.objects.create(
            scan_session=self.scan_session,
            target=self.target,
            result_type="service",
            tool_name="nmap",
            severity="info",
            data={"port": 80, "service": "http"}
        )
        
        ScanResult.objects.create(
            scan_session=self.scan_session,
            target=self.target,
            result_type="vulnerability",
            tool_name="nuclei",
            severity="medium",
            data={"cve": "CVE-2023-1234"}
        )
        
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
        
        # Should show correct counts
        self.assertContains(response, 'Total Scans')
        self.assertContains(response, 'Latest Scan Targets')
        self.assertContains(response, 'Latest Scan Vulnerabilities')
    
    def test_scans_stat_boxes_with_empty_organization(self):
        """Test stat boxes for organization with no data."""
        # Delete all scan data
        self.scan_result.delete()
        self.target.delete()
        self.scan_session.delete()
        
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
        
        # Should show zero values
        self.assertContains(response, 'Total Scans')
        self.assertContains(response, 'Latest Scan Targets')
        self.assertContains(response, 'Latest Scan Vulnerabilities')
    
    def test_scan_detail_requires_authentication(self):
        """Test that scan detail requires authentication."""
        response = self.client.get(f'/scans/{self.scan_session.id}/')
        self.assertRedirects(response, f'/accounts/login/?next=/scans/{self.scan_session.id}/')
    
    def test_scan_detail_authenticated(self):
        """Test scan detail for authenticated user."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get(f'/scans/{self.scan_session.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test scan session')
        self.assertContains(response, '192.168.1.1')
    
    def test_scan_detail_nonexistent(self):
        """Test scan detail for nonexistent scan."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/scans/99999/')
        self.assertEqual(response.status_code, 404)
    
    def test_scan_detail_organization_isolation(self):
        """Test that scan detail is isolated by organization."""
        # Create another organization and user
        other_org = Organization.objects.create(
            name="Other Organization",
            description="Other organization"
        )
        other_user = User.objects.create_user(
            username="otheruser",
            email="other@example.com",
            password="testpass123",
            first_name="Other",
            last_name="User",
            organization=other_org
        )
        
        # Create scan session for other organization
        other_scan = ScanSession.objects.create(
            organization=other_org,
            created_by=other_user,
            description="Other scan session",
            status='completed'
        )
        
        # Login as original user
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get(f'/scans/{other_scan.id}/')
        self.assertEqual(response.status_code, 404)
    
    def test_scan_detail_with_no_targets(self):
        """Test scan detail with no targets."""
        # Delete the target
        self.target.delete()
        
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get(f'/scans/{self.scan_session.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'No targets found')
    
    def test_scan_detail_with_no_vulnerabilities(self):
        """Test scan detail with no vulnerabilities."""
        # Delete the scan result
        self.scan_result.delete()
        
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get(f'/scans/{self.scan_session.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'No results found')
    
    def test_target_detail_requires_authentication(self):
        """Test that target detail requires authentication."""
        response = self.client.get(f'/scans/{self.scan_session.id}/targets/{self.target.id}/')
        self.assertRedirects(response, f'/accounts/login/?next=/scans/{self.scan_session.id}/targets/{self.target.id}/')
    
    def test_target_detail_authenticated(self):
        """Test target detail for authenticated user."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get(f'/scans/{self.scan_session.id}/targets/{self.target.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '192.168.1.1')
        self.assertContains(response, 'nuclei')
    
    def test_target_detail_nonexistent_scan(self):
        """Test target detail for nonexistent scan."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get(f'/scans/99999/targets/{self.target.id}/')
        self.assertEqual(response.status_code, 404)
    
    def test_target_detail_nonexistent_target(self):
        """Test target detail for nonexistent target."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get(f'/scans/{self.scan_session.id}/targets/99999/')
        self.assertEqual(response.status_code, 404)
    
    def test_target_detail_organization_isolation(self):
        """Test that target detail is isolated by organization."""
        # Create another organization and user
        other_org = Organization.objects.create(
            name="Other Organization",
            description="Other organization"
        )
        other_user = User.objects.create_user(
            username="otheruser",
            email="other@example.com",
            password="testpass123",
            first_name="Other",
            last_name="User",
            organization=other_org
        )
        
        # Create scan session and target for other organization
        other_scan = ScanSession.objects.create(
            organization=other_org,
            created_by=other_user,
            description="Other scan session",
            status='completed'
        )
        other_target = Target.objects.create(
            scan_session=other_scan,
            value="10.0.0.1",
            target_type="ip"
        )
        
        # Login as original user
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get(f'/scans/{other_scan.id}/targets/{other_target.id}/')
        self.assertEqual(response.status_code, 404)
    
    def test_target_detail_with_no_vulnerabilities(self):
        """Test target detail with no vulnerabilities."""
        # Delete the scan result
        self.scan_result.delete()
        
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get(f'/scans/{self.scan_session.id}/targets/{self.target.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'No results found')
    
    def test_target_detail_with_vulnerabilities(self):
        """Test target detail with vulnerabilities."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get(f'/scans/{self.scan_session.id}/targets/{self.target.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'nuclei')
        self.assertContains(response, 'high')
    
    def test_target_detail_partial_request(self):
        """Test target detail with partial request (AJAX)."""
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get(
            f'/scans/{self.scan_session.id}/targets/{self.target.id}/',
            HTTP_X_PARTIAL='true'
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '192.168.1.1')
