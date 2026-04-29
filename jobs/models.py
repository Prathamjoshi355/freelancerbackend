from datetime import datetime

from mongoengine import (
    DateTimeField,
    Document,
    FloatField,
    IntField,
    ListField,
    ReferenceField,
    StringField,
)

from accounts.models import CustomUser


class Job(Document):
    meta = {
        "collection": "jobs",
        "indexes": ["client", "status", "created_at", "required_skill_slugs"],
    }

    client = ReferenceField(CustomUser, required=True)
    title = StringField(required=True, max_length=200)
    description = StringField(required=True)
    budget_min = FloatField(required=True)
    budget_max = FloatField(required=True)
    required_skill_slugs = ListField(StringField(), default=list)
    status = StringField(required=True, choices=["open", "closed", "completed", "cancelled"], default="open")
    hired_freelancer = ReferenceField(CustomUser)
    hired_bid_id = StringField()
    bid_count = IntField(default=0)
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)


class Contract(Document):
    meta = {
        "collection": "contracts",
        "indexes": [{"fields": ["job"], "unique": True}, "client", "freelancer", "status"],
    }

    job = ReferenceField(Job, required=True, unique=True)
    client = ReferenceField(CustomUser, required=True)
    freelancer = ReferenceField(CustomUser, required=True)
    bid_id = StringField(required=True)
    agreed_amount = FloatField(required=True)
    status = StringField(required=True, choices=["active", "funded", "completed", "cancelled"], default="active")
    payment_status = StringField(required=True, choices=["unpaid", "paid"], default="unpaid")
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
    completed_at = DateTimeField()

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)


class Review(Document):
    meta = {
        "collection": "reviews",
        "indexes": [{"fields": ["contract"], "unique": True}, "freelancer", "client", "created_at"],
    }

    contract = ReferenceField(Contract, required=True, unique=True)
    job = ReferenceField(Job, required=True)
    client = ReferenceField(CustomUser, required=True)
    freelancer = ReferenceField(CustomUser, required=True)
    rating = IntField(required=True, min_value=1, max_value=5)
    comment = StringField()
    client_rating = IntField(min_value=1, max_value=5)
    client_comment = StringField()
    client_reviewed_at = DateTimeField()
    created_at = DateTimeField(default=datetime.utcnow)
