from mongoengine import Document, StringField, EmailField, BooleanField, DateTimeField, ReferenceField
from datetime import datetime
from django.contrib.auth.hashers import make_password, check_password

class CustomUser(Document):
    """MongoDB User Model"""
    meta = {
        'collection': 'custom_users',
        'indexes': ['email']
    }
    
    email = EmailField(required=True, unique=True)
    password = StringField(required=True)
    full_name = StringField(max_length=100)
    company_name = StringField(max_length=150)
    role = StringField(
        max_length=20,
        choices=['freelancer', 'client'],
        default='freelancer'
    )
    is_active = BooleanField(default=True)
    is_staff = BooleanField(default=False)
    is_superuser = BooleanField(default=False)
    
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
    
    @property
    def pk(self):
        """Return string representation of MongoDB ObjectId for Django compatibility"""
        return str(self.id)
    
    @property
    def is_authenticated(self):
        """Return True if user is authenticated (always True for saved users)"""
        return True
    
    def set_password(self, raw_password):
        """Hash and set password"""
        self.password = make_password(raw_password)
        self.save()
    
    def check_password(self, raw_password):
        """Check if password is correct"""
        return check_password(raw_password, self.password)
    
    def __str__(self):
        return self.email
    
    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        super().save(*args, **kwargs)

