from rest_framework import serializers
from .models import Conversation, Message


class MessageSerializer(serializers.Serializer):
    """Serializer for Message model"""
    id = serializers.CharField(read_only=True)
    conversation_id = serializers.CharField()
    sender_id = serializers.CharField()
    
    content = serializers.CharField()
    is_read = serializers.BooleanField(default=False)
    read_at = serializers.DateTimeField(required=False, allow_null=True)
    attachment_url = serializers.URLField(required=False, allow_null=True)
    
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)


class ConversationSerializer(serializers.Serializer):
    """Serializer for Conversation model"""
    id = serializers.CharField(read_only=True)
    participant_ids = serializers.ListField(child=serializers.CharField())
    subject = serializers.CharField(required=False)
    
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)


class ConversationDetailSerializer(ConversationSerializer):
    """Detailed conversation with recent messages"""
    participant_info = serializers.SerializerMethodField()
    recent_messages = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()
    
    def get_participant_info(self, obj):
        participants = []
        for participant in obj.participant_ids:
            participants.append({
                'id': str(participant.id),
                'email': participant.email,
                'full_name': participant.full_name,
            })
        return participants
    
    def get_recent_messages(self, obj):
        messages = Message.objects.filter(conversation_id=obj).limit(10)
        return MessageSerializer(messages, many=True).data
    
    def get_unread_count(self, obj):
        request = self.context.get('request')
        if request:
            unread = Message.objects.filter(
                conversation_id=obj,
                is_read=False
            ).exclude(sender_id=request.user)
            return unread.count()
        return 0
