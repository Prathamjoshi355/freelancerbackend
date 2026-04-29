from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView

from core.policies import (
    get_or_create_profile,
    get_workflow_state,
    serialize_datetime,
    sync_user_account_status,
    verify_face_for_user,
)
from profiles.serializers import serialize_profile
from .serializers import (
    FaceVerificationSerializer,
    MarketplaceTokenObtainPairSerializer,
    RegistrationSerializer,
    serialize_user,
)


class AuthThrottle(AnonRateThrottle):
    scope = "auth"


class RegistrationThrottle(AnonRateThrottle):
    scope = "registration"


class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [RegistrationThrottle]

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        profile = get_or_create_profile(user)
        sync_user_account_status(user)

        token_serializer = MarketplaceTokenObtainPairSerializer(
            data={"email": user.email, "password": request.data.get("password")}
        )
        token_serializer.is_valid(raise_exception=True)

        return Response(
            {
                "message": "Registration successful. Complete your profile to unlock marketplace access.",
                "user": serialize_user(user),
                "profile": serialize_profile(profile, include_private=True),
                "workflow": get_workflow_state(user),
                **token_serializer.validated_data,
            },
            status=status.HTTP_201_CREATED,
        )


class MarketplaceTokenView(TokenObtainPairView):
    serializer_class = MarketplaceTokenObtainPairSerializer
    permission_classes = [AllowAny]
    throttle_classes = [AuthThrottle]


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        profile = get_or_create_profile(user)
        workflow = get_workflow_state(user)

        return Response(
            {
                "user": serialize_user(user),
                "profile": serialize_profile(profile, include_private=True),
                "workflow": workflow,
                "stats": self._build_stats(user),
            }
        )

    def _build_stats(self, user):
        if user.role == "client":
            from jobs.models import Contract, Job

            return {
                "open_jobs": Job.objects(client=user, status="open").count(),
                "closed_jobs": Job.objects(client=user, status="closed").count(),
                "active_contracts": Contract.objects(client=user, status__in=["active", "funded"]).count(),
            }

        from bidding.models import Bid
        from jobs.models import Contract
        from skill_tests.models import FreelancerSkill

        return {
            "active_bids": Bid.objects(freelancer=user, status="pending").count(),
            "active_contracts": Contract.objects(freelancer=user, status__in=["active", "funded"]).count(),
            "passed_skills": FreelancerSkill.objects(user=user, test_status="passed").count(),
        }


class FaceLoginVerifyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = FaceVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        matched, distance = verify_face_for_user(request.user, serializer.validated_data["face_image"])
        if not matched:
            return Response(
                {"verified": False, "distance": distance, "detail": "Face verification failed."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.user.last_login_at = timezone.now()
        request.user.save()
        return Response(
            {
                "verified": True,
                "distance": distance,
                "verified_at": serialize_datetime(request.user.last_login_at),
            }
        )
