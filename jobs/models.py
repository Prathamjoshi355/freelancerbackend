from mongoengine import Document, StringField, DateTimeField, ReferenceField, ListField, FloatField, IntField, BooleanField
from datetime import datetime
from accounts.models import CustomUser

class Job(Document):
    """Job Posting Model"""
    meta = {
        'collection': 'jobs',
        'indexes': ['client_id', 'status', 'created_at', 'category']
    }
    
    # Job basic info
    client_id = ReferenceField(CustomUser, required=True)
    title = StringField(required=True, max_length=200)
    description = StringField(required=True)
    category = StringField(required=True, max_length=100)
    
    # Project details
    budget_type = StringField(choices=['fixed', 'hourly'], default='fixed')
    budget_min = FloatField(required=True)
    budget_max = FloatField(required=True)
    hourly_rate = FloatField()  # if hourly
    duration = StringField(choices=['short', 'medium', 'long'])  # short: <1 month, medium: 1-3 months, long: 3+ months
    
    # Requirements
    required_skills = ListField(StringField())
    experience_level = StringField(choices=['beginner', 'intermediate', 'expert'], default='intermediate')
    
    # Status
    status = StringField(
        choices=['open', 'in_progress', 'completed', 'closed'],
        default='open'
    )
    
    # Metadata
    is_featured = BooleanField(default=False)
    views_count = IntField(default=0)
    proposals_count = IntField(default=0)
    
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
    deadline = DateTimeField()
    
    def __str__(self):
        return self.title
    
    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        super().save(*args, **kwargs)


class JobApplication(Document):
    """Track freelancer applications to jobs"""
    meta = {
        'collection': 'job_applications',
        'indexes': ['job_id', 'freelancer_id']
    }
    
    job_id = ReferenceField(Job, required=True)
    freelancer_id = ReferenceField(CustomUser, required=True)
    status = StringField(
        choices=['pending', 'accepted', 'rejected'],
        default='pending'
    )
    
    applied_at = DateTimeField(default=datetime.utcnow)
