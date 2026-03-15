from rest_framework import serializers
from .models import Notification, NotificationPreference


class NotificationSerializer(serializers.Serializer):
    """Serializer for Notification model"""
    id = serializers.CharField(read_only=True)
    user_id = serializers.CharField()
    
    title = serializers.CharField()
    message = serializers.CharField()
    
    notification_type = serializers.ChoiceField(
        choices=['job_posted', 'proposal_received', 'proposal_accepted', 
                'proposal_rejected', 'payment_received', 'message_received', 
                'job_completed', 'review_received']
    )
    
    related_id = serializers.CharField(required=False)
    is_read = serializers.BooleanField(default=False)
    read_at = serializers.DateTimeField(required=False, allow_null=True)
    
    created_at = serializers.DateTimeField(read_only=True)
    
    def create(self, validated_data):
        notification = Notification(**validated_data)
        notification.save()
        return notification


class NotificationPreferenceSerializer(serializers.Serializer):
    """Serializer for Notification Preferences"""
    id = serializers.CharField(read_only=True)
    user_id = serializers.CharField()
    
    email_on_proposal = serializers.BooleanField(default=True)
    email_on_message = serializers.BooleanField(default=True)
    email_on_payment = serializers.BooleanField(default=True)
    email_on_review = serializers.BooleanField(default=True)
    
    push_notifications_enabled = serializers.BooleanField(default=True)
    sms_notifications_enabled = serializers.BooleanField(default=False)
    
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    
    def create(self, validated_data):
        preference = NotificationPreference(**validated_data)
        preference.save()
        return preference
    
    def update(self, instance, validated_data):
        for field, value in validated_data.items():
            setattr(instance, field, value)
        instance.save()
        return instance
