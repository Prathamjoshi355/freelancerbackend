from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.policies import (
    ensure_clean_text,
    ensure_safe_public_url,
    get_or_create_profile,
    get_workflow_state,
    refresh_profile_completion,
    require_profile_complete,
    sync_user_account_status,
)
from skill_tests.models import FreelancerSkill
from .serializers import ProfileUpdateSerializer, serialize_profile, serialize_profile_summary


class ProfileMeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile = get_or_create_profile(request.user)
        refresh_profile_completion(profile)
        profile.save()
        sync_user_account_status(request.user)
        return Response(
            {
                "profile": serialize_profile(profile, include_private=True),
                "workflow": get_workflow_state(request.user),
            }
        )

    def put(self, request):
        profile = get_or_create_profile(request.user)
        serializer = ProfileUpdateSerializer(
            data=request.data,
            partial=True,
            context={"request": request, "profile": profile},
        )
        serializer.is_valid(raise_exception=True)

        for field, value in serializer.validated_data.items():
            if field in {"description", "bio", "internal_contact_info"}:
                ensure_clean_text(request.user, value, field)
            if field in {"profile_photo_url", "portfolio_url", "github_url", "linkedin_url", "website_url"}:
                ensure_safe_public_url(request.user, value, field)
            if field == "portfolio_items":
                for index, item in enumerate(value):
                    for text_key in {"title", "description"}:
                        ensure_clean_text(
                            request.user,
                            item.get(text_key, ""),
                            f"portfolio_items[{index}].{text_key}",
                        )
                    for url_key in {"live_url", "github_url"}:
                        ensure_safe_public_url(
                            request.user,
                            item.get(url_key, ""),
                            f"portfolio_items[{index}].{url_key}",
                        )
                    for media_index, media_url in enumerate(item.get("media_urls") or []):
                        ensure_safe_public_url(
                            request.user,
                            media_url,
                            f"portfolio_items[{index}].media_urls[{media_index}]",
                        )
            if field == "work_history":
                for index, item in enumerate(value):
                    for text_key in {"title", "company", "summary"}:
                        ensure_clean_text(
                            request.user,
                            item.get(text_key, ""),
                            f"work_history[{index}].{text_key}",
                        )
            if field == "education":
                for index, item in enumerate(value):
                    for text_key in {"school", "degree"}:
                        ensure_clean_text(
                            request.user,
                            item.get(text_key, ""),
                            f"education[{index}].{text_key}",
                        )
            if field == "certifications":
                for index, item in enumerate(value):
                    for text_key in {"name", "issuer"}:
                        ensure_clean_text(
                            request.user,
                            item.get(text_key, ""),
                            f"certifications[{index}].{text_key}",
                        )
                    ensure_safe_public_url(
                        request.user,
                        item.get("credential_url", ""),
                        f"certifications[{index}].credential_url",
                    )
            setattr(profile, field, value)

        refresh_profile_completion(profile)
        profile.save()
        sync_user_account_status(request.user)
        return Response(
            {
                "message": "Profile updated successfully.",
                "profile": serialize_profile(profile, include_private=True),
                "workflow": get_workflow_state(request.user),
            }
        )

    patch = put


class FreelancerDirectoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        require_profile_complete(request.user)
        q = (request.query_params.get("q") or "").strip().lower()
        category_filter = (request.query_params.get("category") or "").strip().lower()
        skill_filter = (request.query_params.get("skill") or "").strip().lower()
        experience_filter = (request.query_params.get("experience_level") or "").strip().lower()

        from .models import Profile

        results = []
        queryset = Profile.objects(role="freelancer", is_complete=True)
        for profile in queryset:
            workflow = get_workflow_state(profile.user)
            if not workflow["can_bid"]:
                continue
            if skill_filter and skill_filter not in (profile.selected_skill_slugs or []):
                continue
            if experience_filter and (profile.experience_level or "").lower() != experience_filter:
                continue

            search_blob = " ".join(
                [
                    profile.full_name or "",
                    profile.username or "",
                    profile.professional_title or "",
                    profile.bio or "",
                    " ".join(profile.selected_skill_slugs or []),
                    " ".join(profile.categories or []),
                ]
            ).lower()
            if q and q not in search_blob:
                continue

            if category_filter and category_filter != "all":
                category_values = [str(item).strip().lower() for item in (profile.categories or [])]
                skill_values = [str(item).strip().lower() for item in (profile.selected_skill_slugs or [])]
                if category_filter not in category_values and category_filter not in skill_values:
                    continue

            passed_skills = FreelancerSkill.objects(user=profile.user, test_status="passed")
            summary = serialize_profile_summary(profile)
            results.append(
                {
                    **summary,
                    "skills": [
                        {
                            "slug": mapping.skill.slug,
                            "name": mapping.skill.name,
                            "rating": round(float(mapping.rating or 0), 2),
                        }
                        for mapping in passed_skills
                    ],
                }
            )

        results.sort(
            key=lambda item: (
                float(item.get("system_metrics", {}).get("visibility_score", 0)),
                float(item.get("overall_rating", 0)),
            ),
            reverse=True,
        )
        return Response({"results": results})
