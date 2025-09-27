from rest_framework import generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from .models import Organization
from .serializers import OrganizationSerializer


class OrganizationListView(generics.ListAPIView):
    """
    List all organizations (admin only).
    """
    queryset = Organization.objects.filter(is_active=True)
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAdminUser]


class OrganizationDetailView(generics.RetrieveUpdateAPIView):
    """
    Retrieve and update organization details.
    Only organization admins can update their organization.
    """
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return Organization.objects.all()
        return Organization.objects.filter(id=user.organization.id)

    def get_object(self):
        user = self.request.user
        if user.is_superuser:
            return super().get_object()
        return user.organization

    def update(self, request, *args, **kwargs):
        user = request.user
        if not user.can_manage_organization():
            return Response(
                {'error': 'You do not have permission to update this organization'},
                status=403
            )
        return super().update(request, *args, **kwargs)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def my_organization(request):
    """
    Get current user's organization details.
    """
    organization = request.user.organization
    if not organization:
        return Response(
            {'error': 'User is not associated with any organization'},
            status=404
        )
    
    serializer = OrganizationSerializer(organization)
    return Response(serializer.data)
