import os
import uuid

import cloudinary
import cloudinary.uploader
from rest_framework.exceptions import ValidationError


cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True,
)


def upload_file(file_obj, folder: str, resource_type: str = "auto"):
    if not file_obj:
        raise ValidationError("No file uploaded.")

    try:
        return cloudinary.uploader.upload(
            file_obj,
            folder=folder,
            public_id=f"{folder}/{uuid.uuid4()}",
            resource_type=resource_type,
            overwrite=False,
        )
    except Exception as exc:
        raise ValidationError(f"Cloud upload failed: {exc}")
