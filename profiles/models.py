from mongoengine import Document, StringField, DateTimeField, ReferenceField, ListField, FloatField, IntField, BooleanField, ObjectIdField
from datetime import datetime
from accounts.models import CustomUser

class Profile(Document):
    """User Profile in MongoDB"""
    meta = {
        'collection': 'profiles',
        'indexes': ['user_id']
    }
    
    user_id = ReferenceField(CustomUser, required=True, unique=True)
    bio = StringField(max_length=500)
    avatar = StringField()
    phone = StringField()
    address = StringField()
    city = StringField()
    country = StringField()
    skills = ListField(StringField())
    rating = FloatField(default=0.0)
    total_projects = IntField(default=0)
    hourly_rate = FloatField()
    profile_completed = BooleanField(default=False)
    
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
    
    def __str__(self):
        return f"{self.user_id.email} Profile"
    
    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        super().save(*args, **kwargs)


class SkillTest(Document):
    """Skill tests for freelancers"""
    meta = {
        'collection': 'skill_tests',
        'indexes': ['user_id', 'skill']
    }
    
    user_id = ReferenceField(CustomUser, required=True)
    skill = StringField(required=True)
    score = FloatField()
    passed = BooleanField(default=False)
    completed_at = DateTimeField()
    created_at = DateTimeField(default=datetime.utcnow)
    
    def __str__(self):
        return f"{self.user_id.email} - {self.skill} Test"


