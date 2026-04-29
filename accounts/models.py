from datetime import datetime

from django.contrib.auth.hashers import check_password, make_password
from mongoengine import (
    BooleanField,
    DateTimeField,
    Document,
    EmailField,
    FloatField,
    IntField,
    ListField,
    ReferenceField,
    StringField,
)


class CustomUser(Document):
    meta = {
        "collection": "users",
        "indexes": ["email", "role", "account_status", "is_restricted"],
    }

    ROLE_CHOICES = ("client", "freelancer")
    STATUS_CHOICES = (
        "pending_profile",
        "pending_skill_selection",
        "pending_skill_tests",
        "active",
        "restricted",
    )

    email = EmailField(required=True, unique=True)
    password = StringField(required=True)
    role = StringField(required=True, choices=ROLE_CHOICES)
    account_status = StringField(default="pending_profile", choices=STATUS_CHOICES)
    email_verified = BooleanField(default=True)
    face_verified = BooleanField(default=False)
    phone_verified = BooleanField(default=False)
    identity_verified = BooleanField(default=False)
    violation_count = IntField(default=0)
    is_restricted = BooleanField(default=False)
    restriction_reason = StringField()
    is_active = BooleanField(default=True)
    is_staff = BooleanField(default=False)
    is_superuser = BooleanField(default=False)
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
    last_login_at = DateTimeField()

    @property
    def pk(self):
        return str(self.id)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)

    def __str__(self):
        return self.email


class FaceEmbedding(Document):
    meta = {
        "collection": "face_embeddings",
        "indexes": [{"fields": ["user"], "unique": True}, "created_at"],
    }

    user = ReferenceField(CustomUser, required=True, unique=True)
    vector = ListField(FloatField(), required=True)
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)
