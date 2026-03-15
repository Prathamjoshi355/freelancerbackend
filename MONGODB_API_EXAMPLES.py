"""
Example MongoDB-Compatible Views for DRF

Update your views/serializers to work with MongoEngine models
"""

from rest_framework import serializers, viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from accounts.models import CustomUser
from profiles.models import Profile

# ==================== SERIALIZERS ====================

class CustomUserSerializer(serializers.Serializer):
    """Serializer for CustomUser MongoEngine model"""
    id = serializers.CharField(read_only=True)
    email = serializers.EmailField()
    full_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    company_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    role = serializers.ChoiceField(choices=['freelancer', 'client'])
    is_active = serializers.BooleanField()
    is_staff = serializers.BooleanField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    
    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = CustomUser(**validated_data)
        if password:
            user.set_password(password)
        user.save()
        return user
    
    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class ProfileSerializer(serializers.Serializer):
    """Serializer for Profile MongoEngine model"""
    id = serializers.CharField(read_only=True)
    user_id = serializers.SerializerMethodField()
    bio = serializers.CharField(required=False, allow_blank=True)
    avatar = serializers.CharField(required=False, allow_blank=True)
    phone = serializers.CharField(required=False, allow_blank=True)
    skills = serializers.ListField(child=serializers.CharField())
    rating = serializers.FloatField(read_only=True)
    total_projects = serializers.IntegerField(read_only=True)
    hourly_rate = serializers.FloatField(required=False)
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    
    def get_user_id(self, obj):
        return str(obj.user_id.id)
    
    def create(self, validated_data):
        profile = Profile(**validated_data)
        profile.save()
        return profile
    
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


# ==================== VIEWSETS ====================

class CustomUserViewSet(viewsets.ViewSet):
    """ViewSet for CustomUser CRUD operations"""
    
    def list(self, request):
        """List all users"""
        users = CustomUser.objects()
        serializer = CustomUserSerializer(users, many=True)
        return Response(serializer.data)
    
    def create(self, request):
        """Create a new user"""
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(
                CustomUserSerializer(user).data,
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def retrieve(self, request, pk=None):
        """Get a single user by ID"""
        try:
            from bson.objectid import ObjectId
            user = CustomUser.objects.get(id=ObjectId(pk))
            serializer = CustomUserSerializer(user)
            return Response(serializer.data)
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    def update(self, request, pk=None):
        """Update a user"""
        try:
            from bson.objectid import ObjectId
            user = CustomUser.objects.get(id=ObjectId(pk))
            serializer = CustomUserSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                updated_user = serializer.save()
                return Response(CustomUserSerializer(updated_user).data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    def destroy(self, request, pk=None):
        """Delete a user"""
        try:
            from bson.objectid import ObjectId
            user = CustomUser.objects.get(id=ObjectId(pk))
            user.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=False, methods=['post'])
    def login(self, request):
        """Login endpoint"""
        email = request.data.get('email')
        password = request.data.get('password')
        
        try:
            user = CustomUser.objects.get(email=email)
            if user.check_password(password):
                serializer = CustomUserSerializer(user)
                return Response(serializer.data)
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class ProfileViewSet(viewsets.ViewSet):
    """ViewSet for Profile CRUD operations"""
    
    def list(self, request):
        """List all profiles"""
        profiles = Profile.objects()
        serializer = ProfileSerializer(profiles, many=True)
        return Response(serializer.data)
    
    def create(self, request):
        """Create a new profile"""
        serializer = ProfileSerializer(data=request.data)
        if serializer.is_valid():
            profile = serializer.save()
            return Response(
                ProfileSerializer(profile).data,
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def retrieve(self, request, pk=None):
        """Get a single profile by ID"""
        try:
            from bson.objectid import ObjectId
            profile = Profile.objects.get(id=ObjectId(pk))
            serializer = ProfileSerializer(profile)
            return Response(serializer.data)
        except Profile.DoesNotExist:
            return Response(
                {'error': 'Profile not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    def update(self, request, pk=None):
        """Update a profile"""
        try:
            from bson.objectid import ObjectId
            profile = Profile.objects.get(id=ObjectId(pk))
            serializer = ProfileSerializer(profile, data=request.data, partial=True)
            if serializer.is_valid():
                updated_profile = serializer.save()
                return Response(ProfileSerializer(updated_profile).data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Profile.DoesNotExist:
            return Response(
                {'error': 'Profile not found'},
                status=status.HTTP_404_NOT_FOUND
            )


# ==================== URL CONFIGURATION ====================

"""
In your urls.py, add:

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from accounts.views import CustomUserViewSet
from profiles.views import ProfileViewSet

router = DefaultRouter()
router.register(r'users', CustomUserViewSet, basename='user')
router.register(r'profiles', ProfileViewSet, basename='profile')

urlpatterns = [
    path('api/', include(router.urls)),
]
"""
