from datetime import datetime

from mongoengine import DateTimeField, DictField, Document, FloatField, ReferenceField, StringField

from accounts.models import CustomUser
from jobs.models import Contract, Job


class Payment(Document):
    meta = {
        "collection": "payments",
        "indexes": [{"fields": ["contract"], "unique": True}, "client", "freelancer", "status", "created_at"],
    }

    contract = ReferenceField(Contract, required=True, unique=True)
    job = ReferenceField(Job, required=True)
    client = ReferenceField(CustomUser, required=True)
    freelancer = ReferenceField(CustomUser, required=True)
    amount = FloatField(required=True)
    currency = StringField(default="INR")
    provider = StringField(default="razorpay")
    provider_mode = StringField(default="mock")
    status = StringField(required=True, choices=["created", "verified", "failed"], default="created")
    provider_order_id = StringField()
    provider_payment_id = StringField()
    provider_signature = StringField()
    provider_payload = DictField()
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
    verified_at = DateTimeField()

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)
