from datetime import datetime

from mongoengine import DateTimeField, Document, ListField, ReferenceField, StringField

from accounts.models import CustomUser
from jobs.models import Contract


class Conversation(Document):
    meta = {
        "collection": "conversations",
        "indexes": [{"fields": ["contract"], "unique": True}, "updated_at"],
    }

    contract = ReferenceField(Contract, required=True, unique=True)
    participant_ids = ListField(ReferenceField(CustomUser), default=list)
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)


class Message(Document):
    meta = {
        "collection": "messages",
        "indexes": ["conversation", "sender", "created_at", "status", "attachment_type", "attachment_scan_status"],
    }

    conversation = ReferenceField(Conversation, required=True)
    sender = ReferenceField(CustomUser, required=True)
    content = StringField(default="")
    attachment_url = StringField()
    attachment_name = StringField()
    attachment_type = StringField()
    attachment_extracted_text = StringField()
    attachment_scan_status = StringField(
        choices=["not_applicable", "completed", "failed"],
        default="not_applicable",
    )
    attachment_scan_error = StringField()
    status = StringField(required=True, choices=["sent", "blocked"], default="sent")
    moderation_flags = ListField(StringField(), default=list)
    created_at = DateTimeField(default=datetime.utcnow)
