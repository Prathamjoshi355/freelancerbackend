from rest_framework import status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from profiles.models import Profile
from services.cloudinary import upload_file
from .models import FileUpload
from .serializers import FileUploadSerializer


FIELD_MAP = {
    "profile_image": "profile_image_url",
    "document": "document_url",
    "attachment": "attachment_url",
}


class FileUploadViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def create(self, request):
        serializer = FileUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        file_obj = serializer.validated_data["file"]
        file_type = serializer.validated_data["file_type"]
        result = upload_file(file_obj, folder=f"freelancex/{file_type}")
        url = result.get("secure_url") or result.get("url")

        record = FileUpload(
            user_id=request.user,
            file_url=url,
            file_type=file_type,
            original_name=getattr(file_obj, "name", ""),
        )
        record.save()

        profile = Profile.objects(user_id=request.user).first()
        if profile and file_type in FIELD_MAP:
            setattr(profile, FIELD_MAP[file_type], url)
            profile.save()

        return Response(
            {
                "id": str(record.id),
                "file_url": url,
                "file_type": file_type,
                "original_name": record.original_name,
            },
            status=status.HTTP_201_CREATED,
        )
