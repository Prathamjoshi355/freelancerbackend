from mongoengine import Document, StringField, DateTimeField, ReferenceField, BooleanField, ListField
from datetime import datetime
from accounts.models import CustomUser


class Conversation(Document):
    """Conversation between two users"""
    meta = {
        'collection': 'conversations',
        'indexes': ['participant_ids', 'created_at']
    }
    
    participant_ids = ListField(ReferenceField(CustomUser))
    subject = StringField()  # Job title or context
    
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
    
    def __str__(self):
        return f"Conversation between participants"
    
    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        super().save(*args, **kwargs)


class Message(Document):
    """Message within a conversation"""
    meta = {
        'collection': 'messages',
        'indexes': ['conversation_id', 'sender_id', 'created_at']
    }
    
    conversation_id = ReferenceField(Conversation, required=True)
    sender_id = ReferenceField(CustomUser, required=True)
    content = StringField(required=True)
    
    # Metadata
    is_read = BooleanField(default=False)
    read_at = DateTimeField()
    attachment_url = StringField()  # URL to attachment if any
    
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
    
    def __str__(self):
        return f"Message from {self.sender_id.email}"
    
    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        super().save(*args, **kwargs)
