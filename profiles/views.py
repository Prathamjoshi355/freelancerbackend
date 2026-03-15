from rest_framework import viewsets, generics, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import action
from .models import Profile
from .serializers import ProfileSerializer


class ProfileViewSet(viewsets.ViewSet):
    """ViewSet for Profile operations"""
    
    def list(self, request):
        """List all profiles (public)"""
        profiles = Profile.objects.all()
        serializer = ProfileSerializer(profiles, many=True)
        return Response(serializer.data)
    
    def retrieve(self, request, pk=None):
        """Get profile details"""
        try:
            profile = Profile.objects.get(user_id=pk)
            serializer = ProfileSerializer(profile)
            return Response(serializer.data)
        except Profile.DoesNotExist:
            return Response(
                {'detail': 'Profile not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=False, methods=['get'])
    def my_profile(self, request):
        """Get current user's profile"""
        permission_classes = [IsAuthenticated]
        
        try:
            profile = Profile.objects.get(user_id=request.user)
            serializer = ProfileSerializer(profile)
            return Response(serializer.data)
        except Profile.DoesNotExist:
            # Create default profile if doesn't exist
            profile = Profile(user_id=request.user)
            profile.save()
            serializer = ProfileSerializer(profile)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    @action(detail=False, methods=['post'])
    def update_profile(self, request):
        """Update current user's profile"""
        permission_classes = [IsAuthenticated]
        
        try:
            profile = Profile.objects.get(user_id=request.user)
        except Profile.DoesNotExist:
            profile = Profile(user_id=request.user)
        
        serializer = ProfileSerializer(data=request.data, partial=True)
        if serializer.is_valid():
            for field, value in serializer.validated_data.items():
                setattr(profile, field, value)
            profile.save()
            
            return Response(
                ProfileSerializer(profile).data,
                status=status.HTTP_200_OK
            )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'])
    def freelancers(self, request):
        """Search freelancers by skill"""
        skill = request.query_params.get('skill')
        
        if skill:
            profiles = Profile.objects.filter(skills__contains=skill)
        else:
            profiles = Profile.objects.all()
        
        serializer = ProfileSerializer(profiles, many=True)
        return Response(serializer.data)


class ProfileDetailView(generics.RetrieveUpdateAPIView):
    """Get or update profile"""
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializer
    
    def get_object(self):
        try:
            return Profile.objects.get(user_id=self.request.user)
        except Profile.DoesNotExist:
            profile = Profile(user_id=self.request.user)
            profile.save()
            return profile
