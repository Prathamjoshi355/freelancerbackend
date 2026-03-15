from mongoengine import Document, StringField, DateTimeField, ReferenceField, BooleanField
from datetime import datetime
from accounts.models import CustomUser


class Notification(Document):
    """Notification Model"""
    meta = {
        'collection': 'notifications',
        'indexes': ['user_id', 'created_at', 'is_read']
    }
    
    user_id = ReferenceField(CustomUser, required=True)
    
    # Notification content
    title = StringField(required=True)
    message = StringField(required=True)
    
    # Notification type
    notification_type = StringField(
        choices=['job_posted', 'proposal_received', 'proposal_accepted', 
                'proposal_rejected', 'payment_received', 'message_received', 
                'job_completed', 'review_received'],
        default='message_received'
    )
    
    # Related object reference (job_id, proposal_id, etc.)
    related_id = StringField()
    
    # Status
    is_read = BooleanField(default=False)
    read_at = DateTimeField()
    
    created_at = DateTimeField(default=datetime.utcnow)
    
    def __str__(self):
        return f"Notification for {self.user_id.email} - {self.title}"


class NotificationPreference(Document):
    """User Notification Preferences"""
    meta = {
        'collection': 'notification_preferences',
        'indexes': ['user_id']
    }
    
    user_id = ReferenceField(CustomUser, required=True, unique=True)
    
    # Notification preferences
    email_on_proposal = BooleanField(default=True)
    email_on_message = BooleanField(default=True)
    email_on_payment = BooleanField(default=True)
    email_on_review = BooleanField(default=True)
    
    push_notifications_enabled = BooleanField(default=True)
    sms_notifications_enabled = BooleanField(default=False)
    
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
    
    def __str__(self):
        return f"Notification Preferences for {self.user_id.email}"
    
    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        super().save(*args, **kwargs)
