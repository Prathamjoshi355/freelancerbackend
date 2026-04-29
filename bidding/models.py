from datetime import datetime

from mongoengine import DateTimeField, Document, FloatField, ReferenceField, StringField

from accounts.models import CustomUser
from jobs.models import Job


class Bid(Document):
    meta = {
        "collection": "bids",
        "indexes": [{"fields": ["job", "freelancer"], "unique": True}, "status", "created_at"],
    }

    job = ReferenceField(Job, required=True)
    freelancer = ReferenceField(CustomUser, required=True)
    bid_amount = FloatField(required=True)
    proposal = StringField(required=True)
    status = StringField(
        required=True,
        choices=["pending", "hired", "rejected", "auto_rejected", "withdrawn"],
        default="pending",
    )
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)
