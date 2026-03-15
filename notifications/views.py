from rest_framework import viewsets, generics, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from datetime import datetime
from .models import Notification, NotificationPreference
from .serializers import NotificationSerializer, NotificationPreferenceSerializer


class NotificationViewSet(viewsets.ViewSet):
    """ViewSet for Notification operations"""
    permission_classes = [IsAuthenticated]
    
    def list(self, request):
        """List notifications for current user"""
        # Get filter parameters
        unread_only = request.query_params.get('unread_only', 'false').lower() == 'true'
        
        notifications = Notification.objects.filter(user_id=request.user).order_by('-created_at')
        
        if unread_only:
            notifications = notifications.filter(is_read=False)
        
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data)
    
    def retrieve(self, request, pk=None):
        """Get notification details"""
        try:
            notification = Notification.objects.get(id=pk)
            
            if notification.user_id.id != request.user.id:
                return Response(
                    {'detail': 'You do not have access to this notification'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            serializer = NotificationSerializer(notification)
            return Response(serializer.data)
        except Notification.DoesNotExist:
            return Response(
                {'detail': 'Notification not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=True, methods=['post'])
    def mark_as_read(self, request, pk=None):
        """Mark notification as read"""
        try:
            notification = Notification.objects.get(id=pk)
            
            if notification.user_id.id != request.user.id:
                return Response(
                    {'detail': 'You do not have access to this notification'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            notification.is_read = True
            notification.read_at = datetime.utcnow()
            notification.save()
            
            serializer = NotificationSerializer(notification)
            return Response(serializer.data)
        except Notification.DoesNotExist:
            return Response(
                {'detail': 'Notification not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=False, methods=['post'])
    def mark_all_as_read(self, request):
        """Mark all notifications as read"""
        notifications = Notification.objects.filter(
            user_id=request.user,
            is_read=False
        )
        
        count = 0
        for notification in notifications:
            notification.is_read = True
            notification.read_at = datetime.utcnow()
            notification.save()
            count += 1
        
        return Response({'detail': f'Marked {count} notifications as read'})
    
    @action(detail=False, methods=['get'])
    def unread_count(self, request):
        """Get unread notification count"""
        count = Notification.objects.filter(
            user_id=request.user,
            is_read=False
        ).count()
        
        return Response({'unread_count': count})


class NotificationPreferenceViewSet(viewsets.ViewSet):
    """ViewSet for Notification Preferences"""
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['get'])
    def my_preferences(self, request):
        """Get current user's notification preferences"""
        try:
            preferences = NotificationPreference.objects.get(user_id=request.user)
        except NotificationPreference.DoesNotExist:
            # Create default preferences
            preferences = NotificationPreference(user_id=request.user)
            preferences.save()
        
        serializer = NotificationPreferenceSerializer(preferences)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def update_preferences(self, request):
        """Update notification preferences"""
        try:
            preferences = NotificationPreference.objects.get(user_id=request.user)
        except NotificationPreference.DoesNotExist:
            preferences = NotificationPreference(user_id=request.user)
        
        serializer = NotificationPreferenceSerializer(data=request.data)
        if serializer.is_valid():
            for field, value in serializer.validated_data.items():
                setattr(preferences, field, value)
            preferences.save()
            
            return Response(
                NotificationPreferenceSerializer(preferences).data,
                status=status.HTTP_200_OK
            )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
