from rest_framework import viewsets, generics, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from datetime import datetime
from .models import Conversation, Message
from .serializers import MessageSerializer, ConversationSerializer, ConversationDetailSerializer


class ConversationViewSet(viewsets.ViewSet):
    """ViewSet for Conversation operations"""
    permission_classes = [IsAuthenticated]
    
    
    def list(self, request):
        """List conversations for current user"""
        conversations = Conversation.objects.filter(
            participant_ids=request.user
        ).order_by('-updated_at')
        
        serializer = ConversationDetailSerializer(
            conversations,
            many=True,
            context={'request': request}
        )
        return Response(serializer.data)
    
    def create(self, request):
        """Create or get existing conversation"""
        participant_email = request.data.get('participant_email')
        
        from accounts.models import CustomUser
        try:
            other_user = CustomUser.objects.get(email=participant_email)
        except CustomUser.DoesNotExist:
            return Response(
                {'detail': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if conversation already exists
        existing = Conversation.objects.filter(
            participant_ids=request.user
        ).filter(participant_ids=other_user).first()
        
        if existing:
            serializer = ConversationDetailSerializer(
                existing,
                context={'request': request}
            )
            return Response(serializer.data)
        
        # Create new conversation
        conversation = Conversation(
            participant_ids=[request.user, other_user],
            subject=request.data.get('subject', '')
        )
        conversation.save()
        
        serializer = ConversationDetailSerializer(
            conversation,
            context={'request': request}
        )
        return Response(
            serializer.data,
            status=status.HTTP_201_CREATED
        )
    
    def retrieve(self, request, pk=None):
        """Get conversation details"""
        try:
            conversation = Conversation.objects.get(id=pk)
            
            # Check if user is participant
            if request.user not in conversation.participant_ids:
                return Response(
                    {'detail': 'You do not have access to this conversation'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            serializer = ConversationDetailSerializer(
                conversation,
                context={'request': request}
            )
            return Response(serializer.data)
        except Conversation.DoesNotExist:
            return Response(
                {'detail': 'Conversation not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=True, methods=['get'])
    def messages(self, request, pk=None):
        """Get all messages in a conversation"""
        try:
            conversation = Conversation.objects.get(id=pk)
            
            if request.user not in conversation.participant_ids:
                return Response(
                    {'detail': 'You do not have access to this conversation'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            messages = Message.objects.filter(conversation_id=conversation).order_by('created_at')
            serializer = MessageSerializer(messages, many=True)
            return Response(serializer.data)
        except Conversation.DoesNotExist:
            return Response(
                {'detail': 'Conversation not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class MessageViewSet(viewsets.ViewSet):
    """ViewSet for Message operations"""
    permission_classes = [IsAuthenticated]
    
    def create(self, request):
        """Send a message"""
        conversation_id = request.data.get('conversation_id')
        content = request.data.get('content')
        
        try:
            conversation = Conversation.objects.get(id=conversation_id)
        except Conversation.DoesNotExist:
            return Response(
                {'detail': 'Conversation not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if user is participant
        if request.user not in conversation.participant_ids:
            return Response(
                {'detail': 'You do not have access to this conversation'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        message = Message(
            conversation_id=conversation,
            sender_id=request.user,
            content=content,
            attachment_url=request.data.get('attachment_url')
        )
        message.save()
        
        # Update conversation updated_at
        conversation.updated_at = datetime.utcnow()
        conversation.save()
        
        serializer = MessageSerializer(message)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    @action(detail=False, methods=['post'])
    def mark_as_read(self, request):
        """Mark messages as read in a conversation"""
        conversation_id = request.data.get('conversation_id')
        
        try:
            conversation = Conversation.objects.get(id=conversation_id)
        except Conversation.DoesNotExist:
            return Response(
                {'detail': 'Conversation not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Mark all unread messages from others as read
        messages = Message.objects.filter(
            conversation_id=conversation,
            is_read=False
        ).exclude(sender_id=request.user)
        
        for msg in messages:
            msg.is_read = True
            msg.read_at = datetime.utcnow()
            msg.save()
        
        return Response({'detail': f'Marked {len(messages)} messages as read'})
    
    @action(detail=False, methods=['get'])
    def unread_count(self, request):
        """Get total unread message count"""
        unread = Message.objects.filter(
            conversation_id__participant_ids=request.user,
            is_read=False
        ).exclude(sender_id=request.user)
        
        return Response({'unread_count': len(unread)})
