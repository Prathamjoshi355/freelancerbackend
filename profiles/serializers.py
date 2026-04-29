from rest_framework import serializers

from core.policies import (
    build_client_metrics,
    build_freelancer_metrics,
    build_verification_snapshot,
    normalize_string_list,
    serialize_datetime,
)


def normalize_portfolio_items(items):
    normalized = []
    for item in items or []:
        payload = {
            "title": str(item.get("title") or "").strip(),
            "description": str(item.get("description") or "").strip(),
            "media_urls": normalize_string_list(item.get("media_urls") or []),
            "live_url": str(item.get("live_url") or "").strip(),
            "github_url": str(item.get("github_url") or "").strip(),
            "tech_stack": normalize_string_list(item.get("tech_stack") or []),
        }
        if any(payload.values()):
            normalized.append(payload)
    return normalized


def normalize_history_items(items, allowed_fields):
    normalized = []
    for item in items or []:
        payload = {field: item.get(field) for field in allowed_fields}
        for key, value in list(payload.items()):
            if isinstance(value, str):
                payload[key] = value.strip()
        if any(str(value or "").strip() for value in payload.values()):
            normalized.append(payload)
    return normalized


class ProfileUpdateSerializer(serializers.Serializer):
    full_name = serializers.CharField(required=False, allow_blank=True, max_length=120)
    profile_photo_url = serializers.CharField(required=False, allow_blank=True)
    company_name = serializers.CharField(required=False, allow_blank=True, max_length=160)
    city = serializers.CharField(required=False, allow_blank=True, max_length=80)
    country = serializers.CharField(required=False, allow_blank=True, max_length=80)
    industry = serializers.CharField(required=False, allow_blank=True, max_length=120)
    company_size = serializers.CharField(required=False, allow_blank=True, max_length=80)
    description = serializers.CharField(required=False, allow_blank=True)
    internal_contact_info = serializers.CharField(required=False, allow_blank=True)
    preferred_communication_method = serializers.ChoiceField(
        choices=["platform_chat"], required=False
    )
    typical_response_time_hours = serializers.IntegerField(required=False, min_value=1, max_value=168)

    username = serializers.CharField(required=False, allow_blank=True, max_length=50)
    timezone = serializers.CharField(required=False, allow_blank=True, max_length=80)
    languages_spoken = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )
    professional_title = serializers.CharField(required=False, allow_blank=True, max_length=160)
    bio = serializers.CharField(required=False, allow_blank=True)
    experience_level = serializers.ChoiceField(
        choices=["entry", "intermediate", "expert"], required=False
    )
    years_of_experience = serializers.IntegerField(required=False, min_value=0)
    categories = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )
    portfolio_url = serializers.CharField(required=False, allow_blank=True)
    portfolio_items = serializers.ListField(
        child=serializers.DictField(), required=False, allow_empty=True
    )
    hourly_rate = serializers.FloatField(required=False, min_value=0)
    fixed_project_rate = serializers.FloatField(required=False, min_value=0)
    availability = serializers.ChoiceField(
        choices=["full_time", "part_time", "not_available"], required=False
    )
    working_hours = serializers.CharField(required=False, allow_blank=True, max_length=120)
    work_history = serializers.ListField(
        child=serializers.DictField(), required=False, allow_empty=True
    )
    education = serializers.ListField(
        child=serializers.DictField(), required=False, allow_empty=True
    )
    certifications = serializers.ListField(
        child=serializers.DictField(), required=False, allow_empty=True
    )
    github_url = serializers.CharField(required=False, allow_blank=True)
    linkedin_url = serializers.CharField(required=False, allow_blank=True)
    website_url = serializers.CharField(required=False, allow_blank=True)

    def validate_username(self, value):
        from .models import Profile

        username = str(value or "").strip().lower()
        if not username:
            return ""

        current_profile = self.context.get("profile")
        existing = Profile.objects(username__iexact=username).first()
        if existing and (current_profile is None or str(existing.id) != str(current_profile.id)):
            raise serializers.ValidationError("This handle is already in use.")
        return username

    def validate_languages_spoken(self, value):
        return normalize_string_list(value)

    def validate_categories(self, value):
        return normalize_string_list(value)

    def validate_portfolio_items(self, value):
        return normalize_portfolio_items(value)

    def validate_work_history(self, value):
        return normalize_history_items(value, ["title", "company", "summary", "start_year", "end_year"])

    def validate_education(self, value):
        return normalize_history_items(value, ["school", "degree", "year"])

    def validate_certifications(self, value):
        return normalize_history_items(value, ["name", "issuer", "year", "credential_url"])


def serialize_profile_summary(profile):
    verification = build_verification_snapshot(profile.user, profile)

    payload = {
        "id": str(profile.id),
        "user_id": str(profile.user.id),
        "role": profile.role,
        "full_name": profile.full_name,
        "company_name": profile.company_name,
        "profile_photo_url": profile.profile_photo_url,
        "city": profile.city,
        "country": profile.country,
        "username": profile.username,
        "timezone": profile.timezone,
        "languages_spoken": profile.languages_spoken or [],
        "professional_title": profile.professional_title,
        "bio": profile.bio,
        "categories": profile.categories or [],
        "selected_skill_slugs": profile.selected_skill_slugs or [],
        "overall_rating": round(float(profile.overall_rating or 0), 2),
        "total_completed_jobs": int(profile.total_completed_jobs or 0),
        "verification": verification,
        "is_complete": bool(profile.is_complete),
    }

    if profile.role == "client":
        client_metrics = build_client_metrics(profile.user)
        payload["overall_rating"] = round(float(client_metrics["client_rating"] or 0), 2)
        payload["client_activity"] = {
            "jobs_posted_count": client_metrics["jobs_posted_count"],
            "active_jobs": client_metrics["active_jobs"],
            "hiring_rate": client_metrics["hiring_rate"],
        }
        payload["client_credibility"] = {
            "total_amount_spent": client_metrics["total_amount_spent"],
            "average_project_budget": client_metrics["average_project_budget"],
            "payment_method_verified": client_metrics["payment_method_verified"],
            "client_rating": client_metrics["client_rating"],
        }
    else:
        system_metrics = build_freelancer_metrics(profile.user, profile)
        payload["system_metrics"] = {
            "skill_assessment_score": system_metrics["skill_assessment_score"],
            "portfolio_quality_score": system_metrics["portfolio_quality_score"],
            "communication_rating": system_metrics["communication_rating"],
            "fraud_flag": system_metrics["fraud_flag"],
            "visibility_score": system_metrics["visibility_score"],
        }
        payload["badges"] = system_metrics["badges"]
        payload["portfolio_preview"] = (profile.portfolio_items or [])[:2]

    return payload


def serialize_profile(profile, include_private=False):
    payload = {
        **serialize_profile_summary(profile),
        "description": profile.description,
        "internal_contact_info": profile.internal_contact_info if include_private else "",
        "industry": profile.industry,
        "company_size": profile.company_size,
        "preferred_communication_method": profile.preferred_communication_method,
        "typical_response_time_hours": profile.typical_response_time_hours,
        "experience_level": profile.experience_level,
        "years_of_experience": profile.years_of_experience,
        "portfolio_url": profile.portfolio_url,
        "portfolio_items": profile.portfolio_items or [],
        "hourly_rate": round(float(profile.hourly_rate or 0), 2),
        "fixed_project_rate": round(float(profile.fixed_project_rate or 0), 2),
        "availability": profile.availability,
        "working_hours": profile.working_hours,
        "work_history": profile.work_history or [],
        "education": profile.education or [],
        "certifications": profile.certifications or [],
        "github_url": profile.github_url,
        "linkedin_url": profile.linkedin_url,
        "website_url": profile.website_url,
        "initial_rating": round(float(profile.initial_rating or 0), 2),
        "final_rating": round(float(profile.final_rating or 0), 2),
        "total_reviews": int(profile.total_reviews or 0),
        "completion_percentage": int(profile.completion_percentage or 0),
        "missing_requirements": profile.missing_requirements or [],
        "created_at": serialize_datetime(profile.created_at),
        "updated_at": serialize_datetime(profile.updated_at),
    }

    if profile.role == "client":
        client_metrics = build_client_metrics(profile.user)
        payload["reviews"] = client_metrics["reviews"]
        payload["badges"] = []
        if client_metrics["payment_method_verified"]:
            payload["badges"].append("Payment Verified")
        if client_metrics["hiring_rate"] >= 60:
            payload["badges"].append("Reliable Hirer")
    else:
        system_metrics = build_freelancer_metrics(profile.user, profile)
        payload["reviews"] = system_metrics["reviews"]
        payload["system_metrics"] = {
            key: value for key, value in system_metrics.items() if key not in {"reviews", "badges"}
        }
        payload["badges"] = system_metrics["badges"]

    if include_private:
        payload["internal_contact_info"] = profile.internal_contact_info

    return payload
