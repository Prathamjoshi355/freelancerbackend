import base64
import io
import math
import re
from typing import Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from PIL import Image
from rest_framework.exceptions import PermissionDenied, ValidationError

from core.env import get_env


CONTACT_PATTERNS = {
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", re.IGNORECASE),
    "phone": re.compile(r"\b(?:\+?\d[\d\s().-]{7,}\d)\b"),
    "payment": re.compile(
        r"\b(?:whatsapp|telegram|signal|upi|gpay|google pay|phonepe|paytm|venmo|paypal|direct payment|pay outside)\b",
        re.IGNORECASE,
    ),
}


def serialize_datetime(value):
    return value.isoformat() if value else None


def average(values: Iterable[float]) -> float:
    numbers = [float(item) for item in values if item is not None]
    if not numbers:
        return 0.0
    return sum(numbers) / len(numbers)


def as_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def has_value(value):
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


def normalize_string_list(values: Optional[Iterable[str]]) -> List[str]:
    normalized = []
    seen = set()
    for value in values or []:
        item = str(value or "").strip()
        if not item:
            continue
        lowered = item.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        normalized.append(item)
    return normalized


def compute_face_embedding(image_data: str) -> List[float]:
    if not image_data:
        raise ValidationError("face_image is required.")

    if "," in image_data:
        image_data = image_data.split(",", 1)[1]

    try:
        image_bytes = base64.b64decode(image_data)
        image = Image.open(io.BytesIO(image_bytes)).convert("L").resize((16, 16))
    except Exception as exc:  # pragma: no cover
        raise ValidationError(f"Invalid face image payload: {exc}") from exc

    pixels = list(image.getdata())
    mean = sum(pixels) / len(pixels)
    variance = sum((pixel - mean) ** 2 for pixel in pixels) / len(pixels)
    std = math.sqrt(variance) or 1.0
    return [round((pixel - mean) / std, 6) for pixel in pixels]


def embedding_distance(left: Iterable[float], right: Iterable[float]) -> float:
    left_values = list(left)
    right_values = list(right)
    if len(left_values) != len(right_values):
        return 10**9
    return math.sqrt(sum((a - b) ** 2 for a, b in zip(left_values, right_values)))


def find_duplicate_face(
    embedding: List[float], current_user_id: Optional[str] = None
) -> Tuple[Optional[object], Optional[float]]:
    from accounts.models import FaceEmbedding

    best_match = None
    best_distance = None
    for record in FaceEmbedding.objects:
        if current_user_id and str(record.user.id) == str(current_user_id):
            continue
        distance = embedding_distance(embedding, record.vector)
        if best_distance is None or distance < best_distance:
            best_distance = distance
            best_match = record.user

    threshold = float(get_env("FACE_MATCH_THRESHOLD", 7.5))
    if best_match is not None and best_distance is not None and best_distance < threshold:
        return best_match, best_distance
    return None, best_distance


def verify_face_for_user(user, face_image: str) -> Tuple[bool, Optional[float]]:
    from accounts.models import FaceEmbedding

    embedding = compute_face_embedding(face_image)
    face_record = FaceEmbedding.objects(user=user).first()
    if face_record is None:
        return False, None

    distance = embedding_distance(embedding, face_record.vector)
    threshold = float(get_env("FACE_MATCH_THRESHOLD", 7.5))
    return distance < threshold, distance


def detect_restricted_content(content: str) -> List[str]:
    text = content or ""
    matches = []
    for label, pattern in CONTACT_PATTERNS.items():
        if pattern.search(text):
            matches.append(label)
    return matches


def register_violation(user, reason: str):
    user.violation_count = int(user.violation_count or 0) + 1
    if user.violation_count >= int(get_env("MAX_POLICY_VIOLATIONS", 3)):
        user.is_restricted = True
        user.account_status = "restricted"
        user.restriction_reason = reason
    user.save()


def ensure_clean_text(user, value: str, field_name: str):
    matches = detect_restricted_content(value)
    if matches:
        register_violation(user, f"Attempted prohibited contact sharing in {field_name}")
        raise ValidationError(
            {
                field_name: (
                    f"External contact or payment details are not allowed in {field_name}. "
                    f"Detected: {', '.join(matches)}."
                )
            }
        )


def ensure_safe_public_url(user, value: str, field_name: str):
    url = str(value or "").strip()
    if not url:
        return

    parsed = urlparse(url)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        raise ValidationError({field_name: "Only http and https URLs are allowed."})

    blocked_markers = [
        "mailto:",
        "tel:",
        "wa.me",
        "whatsapp",
        "telegram",
        "signal",
        "upi",
        "paytm",
        "phonepe",
        "paypal",
        "venmo",
    ]
    lowered = url.lower()
    if any(marker in lowered for marker in blocked_markers) or detect_restricted_content(url):
        register_violation(user, f"Attempted restricted link sharing in {field_name}")
        raise ValidationError(
            {field_name: "External contact and off-platform payment links are not allowed here."}
        )


def get_or_create_profile(user):
    from profiles.models import Profile

    profile = Profile.objects(user=user).first()
    if profile is None:
        profile = Profile(user=user, role=user.role)
        refresh_profile_completion(profile)
        profile.save()
    return profile


def compute_portfolio_quality(profile) -> float:
    items = list(profile.portfolio_items or [])
    if not items:
        return 0.0

    scores = []
    for item in items:
        title = str(item.get("title") or "").strip()
        description = str(item.get("description") or "").strip()
        tech_stack = normalize_string_list(item.get("tech_stack") or [])
        media_urls = normalize_string_list(item.get("media_urls") or [])
        live_url = str(item.get("live_url") or "").strip()
        github_url = str(item.get("github_url") or "").strip()

        score = 0.0
        if title:
            score += 20
        if len(description) >= 80:
            score += 25
        elif description:
            score += 12
        if tech_stack:
            score += 20
        if live_url:
            score += 10
        if github_url:
            score += 10
        if media_urls:
            score += 15
        scores.append(min(score, 100.0))

    quantity_bonus = min(len(items) * 3, 10)
    return round(min(average(scores) + quantity_bonus, 100.0), 2)


def build_verification_snapshot(user, profile):
    from payments.models import Payment

    payment_verified = False
    if user.role == "client":
        payment_verified = Payment.objects(client=user, status="verified").first() is not None

    return {
        "email_verified": bool(getattr(user, "email_verified", bool(user.email))),
        "payment_verified": payment_verified,
        "face_verified": bool(user.face_verified),
        "phone_verified": bool(getattr(user, "phone_verified", False) or getattr(profile, "phone_verified", False)),
        "identity_verified": bool(getattr(user, "identity_verified", False) or getattr(profile, "identity_verified", False)),
    }


def build_recent_reviews(user):
    from jobs.models import Review
    from profiles.models import Profile

    reviews = []
    if user.role == "client":
        queryset = Review.objects(client=user, client_rating__gte=1).order_by("-client_reviewed_at", "-created_at")
        for review in queryset[:5]:
            author_profile = Profile.objects(user=review.freelancer).first()
            reviews.append(
                {
                    "author_name": author_profile.full_name if author_profile and author_profile.full_name else review.freelancer.email,
                    "author_role": "freelancer",
                    "job_id": str(review.job.id),
                    "contract_id": str(review.contract.id),
                    "job_title": review.job.title,
                    "rating": int(review.client_rating),
                    "comment": review.client_comment or "",
                    "created_at": serialize_datetime(review.client_reviewed_at or review.created_at),
                }
            )
        return reviews

    queryset = Review.objects(freelancer=user).order_by("-created_at")
    for review in queryset[:5]:
        author_profile = Profile.objects(user=review.client).first()
        reviews.append(
            {
                "author_name": author_profile.company_name if author_profile and author_profile.company_name else (
                    author_profile.full_name if author_profile and author_profile.full_name else review.client.email
                ),
                "author_role": "client",
                "job_id": str(review.job.id),
                "contract_id": str(review.contract.id),
                "job_title": review.job.title,
                "rating": int(review.rating),
                "comment": review.comment or "",
                "created_at": serialize_datetime(review.created_at),
            }
        )
    return reviews


def build_client_metrics(user):
    from jobs.models import Job, Review
    from payments.models import Payment

    jobs = list(Job.objects(client=user))
    jobs_posted_count = len(jobs)
    active_jobs = len([job for job in jobs if job.status == "open"])
    hired_jobs = len([job for job in jobs if job.hired_freelancer is not None])
    hiring_rate = round((hired_jobs / jobs_posted_count) * 100, 2) if jobs_posted_count else 0.0

    verified_payments = list(Payment.objects(client=user, status="verified"))
    total_amount_spent = round(sum(float(payment.amount or 0) for payment in verified_payments), 2)
    average_project_budget = round(
        average(((float(job.budget_min or 0) + float(job.budget_max or 0)) / 2) for job in jobs),
        2,
    )

    review_values = [review.client_rating for review in Review.objects(client=user, client_rating__gte=1)]
    client_rating = round(average(review_values), 2)

    return {
        "jobs_posted_count": jobs_posted_count,
        "active_jobs": active_jobs,
        "hiring_rate": hiring_rate,
        "total_amount_spent": total_amount_spent,
        "average_project_budget": average_project_budget,
        "payment_method_verified": bool(verified_payments),
        "client_rating": client_rating,
        "reviews": build_recent_reviews(user),
    }


def build_badges(user, profile, skill_assessment_score: float, portfolio_quality_score: float, overall_rating: float):
    badges = []
    verification = build_verification_snapshot(user, profile)
    if verification["face_verified"]:
        badges.append("Face Verified")
    if verification["identity_verified"]:
        badges.append("ID Verified")
    if user.role == "freelancer":
        if skill_assessment_score >= 85:
            badges.append("Skill Proven")
        if portfolio_quality_score >= 80:
            badges.append("Portfolio Strong")
        if overall_rating >= 4.7 and int(profile.total_completed_jobs or 0) >= 5:
            badges.append("Top Rated")
        elif overall_rating >= 4.2 and int(profile.total_completed_jobs or 0) < 5:
            badges.append("Rising Talent")
    else:
        client_metrics = build_client_metrics(user)
        if client_metrics["payment_method_verified"]:
            badges.append("Payment Verified")
        if client_metrics["hiring_rate"] >= 60:
            badges.append("Reliable Hirer")
    return badges


def build_freelancer_metrics(user, profile):
    from jobs.models import Review
    from skill_tests.models import FreelancerSkill

    passed_skills = list(FreelancerSkill.objects(user=user, test_status="passed"))
    skill_assessment_score = round(average(skill.rating for skill in passed_skills), 2)
    portfolio_quality_score = compute_portfolio_quality(profile)

    client_reviews = list(Review.objects(freelancer=user))
    review_average = round(average(review.rating for review in client_reviews), 2)
    base_communication = review_average if review_average else 4.5
    communication_rating = round(max(1.0, base_communication - (int(user.violation_count or 0) * 0.4)), 2)

    verification_bonus = 10 if user.face_verified else 0
    rating_score = (float(profile.overall_rating or 0) / 5) * 20
    delivery_score = min(int(profile.total_completed_jobs or 0) * 2, 10)
    penalty = min(int(user.violation_count or 0) * 10, 30)
    visibility_score = round(
        max(
            0.0,
            min(
                100.0,
                25 + (skill_assessment_score * 0.25) + (portfolio_quality_score * 0.25) + rating_score + delivery_score + verification_bonus - penalty,
            ),
        ),
        2,
    )

    return {
        "skill_assessment_score": skill_assessment_score,
        "portfolio_quality_score": portfolio_quality_score,
        "fraud_flag": bool(user.is_restricted or int(user.violation_count or 0) > 0),
        "communication_rating": communication_rating,
        "visibility_score": visibility_score,
        "badges": build_badges(user, profile, skill_assessment_score, portfolio_quality_score, float(profile.overall_rating or 0)),
        "reviews": build_recent_reviews(user),
    }


def refresh_profile_completion(profile):
    if not profile.preferred_communication_method:
        profile.preferred_communication_method = "platform_chat"

    if profile.role == "client":
        required_fields = [
            ("full_name", profile.full_name),
            ("profile_photo_url", profile.profile_photo_url),
            ("city", profile.city),
            ("country", profile.country),
            ("description", profile.description),
        ]
    else:
        required_fields = [
            ("full_name", profile.full_name),
            ("profile_photo_url", profile.profile_photo_url),
            ("username", profile.username),
            ("city", profile.city),
            ("country", profile.country),
            ("timezone", profile.timezone),
            ("languages_spoken", profile.languages_spoken),
            ("professional_title", profile.professional_title),
            ("bio", profile.bio),
            ("experience_level", profile.experience_level),
            ("years_of_experience", profile.years_of_experience),
            ("categories", profile.categories),
            ("hourly_rate", profile.hourly_rate),
            ("availability", profile.availability),
        ]

    missing = [name for name, value in required_fields if not has_value(value)]
    completion_ratio = (len(required_fields) - len(missing)) / max(len(required_fields), 1)
    profile.missing_requirements = missing
    profile.completion_percentage = int(round(completion_ratio * 100))
    profile.is_complete = not missing
    return profile


def require_profile_complete(user):
    if user.is_restricted:
        raise PermissionDenied("Your account is restricted.")

    profile = get_or_create_profile(user)
    refresh_profile_completion(profile)
    profile.save()
    if not profile.is_complete:
        raise PermissionDenied("Complete your profile before using marketplace features.")
    return profile


def require_client_ready(user):
    if user.role != "client":
        raise PermissionDenied("Only clients can perform this action.")
    require_profile_complete(user)
    return get_workflow_state(user)


def require_freelancer_ready(user):
    if user.role != "freelancer":
        raise PermissionDenied("Only freelancers can perform this action.")
    require_profile_complete(user)
    workflow = get_workflow_state(user)
    if not workflow["can_bid"]:
        raise PermissionDenied("Complete your skill selection and pass the required skill tests first.")
    return workflow


def get_workflow_state(user):
    profile = get_or_create_profile(user)
    refresh_profile_completion(profile)
    profile.save()

    workflow = {
        "face_verified": bool(user.face_verified),
        "profile_completed": bool(profile.is_complete),
        "selected_skills_count": 0,
        "completed_skills_count": 0,
        "strict_skill_mode": as_bool(get_env("STRICT_SKILL_TEST_MODE", "false")),
        "skill_requirement_met": user.role == "client",
        "marketplace_access": False,
        "can_post_jobs": False,
        "can_bid": False,
        "can_access_chat": bool(profile.is_complete and not user.is_restricted),
        "can_pay": False,
        "next_step": "complete_profile" if user.face_verified else "face_verification",
    }

    if user.role == "freelancer":
        from skill_tests.models import FreelancerSkill

        selections = list(FreelancerSkill.objects(user=user))
        # A skill is considered completed if test_status is not empty/none (i.e., test has been taken)
        # This includes "completed", "passed", "failed", or any other status indicating a test attempt
        completed = [item for item in selections if item.test_status and item.test_status not in [None, "", "in_progress", "not_started"]]
        workflow["selected_skills_count"] = len(selections)
        workflow["completed_skills_count"] = len(completed)

        if workflow["strict_skill_mode"]:
            workflow["skill_requirement_met"] = bool(selections) and len(completed) == len(selections)
        else:
            workflow["skill_requirement_met"] = len(completed) > 0

        if not user.face_verified:
            workflow["next_step"] = "face_verification"
        elif not profile.is_complete:
            workflow["next_step"] = "complete_profile"
        elif not selections:
            workflow["next_step"] = "select_skills"
        elif not workflow["skill_requirement_met"]:
            workflow["next_step"] = "complete_skill_tests"
        elif user.is_restricted:
            workflow["next_step"] = "restricted"
        else:
            workflow["next_step"] = "marketplace_unlocked"
    else:
        workflow["next_step"] = (
            "restricted"
            if user.is_restricted
            else ("face_verification" if not user.face_verified else ("complete_profile" if not profile.is_complete else "marketplace_unlocked"))
        )

    workflow["marketplace_access"] = bool(
        user.face_verified and profile.is_complete and workflow["skill_requirement_met"] and not user.is_restricted
    )
    workflow["can_post_jobs"] = bool(user.role == "client" and workflow["marketplace_access"])
    workflow["can_bid"] = bool(user.role == "freelancer" and workflow["marketplace_access"])
    workflow["can_pay"] = bool(user.role == "client" and workflow["marketplace_access"])
    return workflow


def sync_user_account_status(user):
    workflow = get_workflow_state(user)
    if user.is_restricted:
        expected = "restricted"
    elif not workflow["profile_completed"]:
        expected = "pending_profile"
    elif user.role == "freelancer" and workflow["selected_skills_count"] == 0:
        expected = "pending_skill_selection"
    elif user.role == "freelancer" and not workflow["skill_requirement_met"]:
        expected = "pending_skill_tests"
    else:
        expected = "active"

    if user.account_status != expected:
        user.account_status = expected
        user.save()
    return expected


def compute_skill_rating(mcq_score: float, practical_score: float) -> float:
    return round((float(mcq_score) * 0.6) + (float(practical_score) * 0.4), 2)


def update_freelancer_ratings(user):
    from jobs.models import Review
    from profiles.models import Profile
    from skill_tests.models import FreelancerSkill

    passed_skills = FreelancerSkill.objects(user=user, test_status="passed")
    skill_assessment_score = round(average(skill.rating for skill in passed_skills), 2)
    initial_rating = round(skill_assessment_score / 20, 2)
    reviews = list(Review.objects(freelancer=user))
    review_scores = [review.rating for review in reviews]
    final_rating = (
        round((initial_rating * 0.4) + (average(review_scores) * 0.6), 2)
        if review_scores
        else initial_rating
    )

    profile = Profile.objects(user=user).first()
    if profile:
        profile.initial_rating = initial_rating
        profile.final_rating = final_rating
        profile.overall_rating = final_rating
        profile.total_reviews = len(review_scores)
        profile.total_completed_jobs = len(reviews)
        profile.save()

    return {
        "skill_assessment_score": skill_assessment_score,
        "initial_rating": initial_rating,
        "final_rating": final_rating,
        "review_count": len(review_scores),
    }
