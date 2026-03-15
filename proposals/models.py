from mongoengine import Document, StringField, DateTimeField, ReferenceField, FloatField, IntField, BooleanField
from datetime import datetime
from accounts.models import CustomUser
from jobs.models import Job


class Proposal(Document):
    """Proposal/Bid Model"""
    meta = {
        'collection': 'proposals',
        'indexes': ['job_id', 'freelancer_id', 'status']
    }
    
    job_id = ReferenceField(Job, required=True)
    freelancer_id = ReferenceField(CustomUser, required=True)
    
    # Proposal details
    cover_letter = StringField(required=True)
    proposed_amount = FloatField(required=True)
    proposed_timeline = StringField()  # e.g., "2 weeks", "1 month"
    
    # Status
    status = StringField(
        choices=['pending', 'accepted', 'rejected', 'withdrew'],
        default='pending'
    )
    
    # Metadata
    rating = FloatField()
    completed = BooleanField(default=False)
    
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
    
    def __str__(self):
        return f"Proposal by {self.freelancer_id.email} for {self.job_id.title}"
    
    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        super().save(*args, **kwargs)
