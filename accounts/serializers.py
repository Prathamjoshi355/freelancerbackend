from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from core.policies import compute_face_embedding, find_duplicate_face, serialize_datetime
from .models import CustomUser, FaceEmbedding


def serialize_user(user):
    return {
        "id": str(user.id),
        "email": user.email,
        "role": user.role,
        "account_status": user.account_status,
        "email_verified": bool(getattr(user, "email_verified", bool(user.email))),
        "face_verified": user.face_verified,
        "phone_verified": bool(getattr(user, "phone_verified", False)),
        "identity_verified": bool(getattr(user, "identity_verified", False)),
        "is_restricted": user.is_restricted,
        "restriction_reason": user.restriction_reason,
        "violation_count": user.violation_count,
        "created_at": serialize_datetime(user.created_at),
    }


class RegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)
    role = serializers.ChoiceField(choices=CustomUser.ROLE_CHOICES)
    face_image = serializers.CharField(write_only=True)

    def validate_email(self, value):
        normalized = value.lower().strip()
        if CustomUser.objects(email=normalized).first():
            raise serializers.ValidationError("This email is already registered.")
        return normalized

    def validate(self, attrs):
        embedding = compute_face_embedding(attrs.get("face_image"))
        duplicate_user, _ = find_duplicate_face(embedding)
        if duplicate_user:
            raise serializers.ValidationError(
                {"face_image": "A matching face already exists. Duplicate accounts are blocked."}
            )
        attrs["face_embedding_vector"] = embedding
        return attrs

    def create(self, validated_data):
        embedding = validated_data.pop("face_embedding_vector")
        validated_data.pop("face_image", None)

        user = CustomUser(
            email=validated_data["email"],
            role=validated_data["role"],
            email_verified=True,
            face_verified=True,
            account_status="pending_profile",
        )
        user.set_password(validated_data["password"])
        user.save()

        FaceEmbedding(user=user, vector=embedding).save()
        return user


class FaceVerificationSerializer(serializers.Serializer):
    face_image = serializers.CharField()


class MarketplaceTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = "email"
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields.pop("username", None)

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["role"] = user.role
        token["account_status"] = user.account_status
        token["restricted"] = user.is_restricted
        return token

    def validate(self, attrs):
        email = attrs.get("email", "").lower().strip()
        password = attrs.get("password")

        user = CustomUser.objects(email=email).first()
        if user is None or not user.check_password(password):
            raise serializers.ValidationError({"detail": "Invalid credentials"})
        if not user.is_active:
            raise serializers.ValidationError({"detail": "User account is disabled"})

        refresh = self.get_token(user)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": serialize_user(user),
        }
