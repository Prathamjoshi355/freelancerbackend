from datetime import datetime

from mongoengine import DateTimeField, Document, ReferenceField, StringField

from accounts.models import CustomUser


class FileUpload(Document):
    meta = {
        "collection": "files",
        "indexes": ["user_id", "file_type", "created_at"],
    }

    user_id = ReferenceField(CustomUser, required=True)
    file_url = StringField(required=True)
    file_type = StringField(required=True)
    original_name = StringField()
    created_at = DateTimeField(default=datetime.utcnow)
