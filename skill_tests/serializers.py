from rest_framework import serializers

from core.policies import serialize_datetime


class SkillSelectionSerializer(serializers.Serializer):
    skill_slugs = serializers.ListField(child=serializers.CharField(), allow_empty=False)


class SkillSubmissionSerializer(serializers.Serializer):
    attempt_id = serializers.CharField()
    mcq_answers = serializers.JSONField()
    practical_answers = serializers.ListField(child=serializers.DictField(), required=False, allow_empty=True)


class SkillReviewSerializer(serializers.Serializer):
    practical_score = serializers.FloatField(min_value=0, max_value=100)
    review_notes = serializers.CharField(required=False, allow_blank=True)


def serialize_skill(skill):
    return {
        "id": str(skill.id),
        "slug": skill.slug,
        "name": skill.name,
        "category": skill.category,
        "description": skill.description,
    }


def serialize_freelancer_skill(mapping):
    return {
        "id": str(mapping.id),
        "skill": serialize_skill(mapping.skill),
        "test_status": mapping.test_status,
        "mcq_stars": round(float(mapping.mcq_stars or 0), 2),
        "practical_stars": round(float(mapping.practical_stars or 0), 2),
        "total_stars": round(float(mapping.total_stars or 0), 2),
        "attempts": int(mapping.attempts or 0),
        "review_mode": mapping.review_mode,
        "review_notes": mapping.review_notes,
        "selected_at": serialize_datetime(mapping.selected_at),
        "reviewed_at": serialize_datetime(mapping.reviewed_at),
    }


def serialize_attempt(attempt):
    return {
        "id": str(attempt.id),
        "skill_slug": attempt.skill.slug,
        "status": attempt.status,
        "mcq_questions": [
            {
                "id": item["id"],
                "prompt": item["prompt"],
                "options": item["options"],
                "difficulty": item["difficulty"],
            }
            for item in attempt.mcq_questions
        ],
        "practical_questions": [
            {
                "id": item["id"],
                "prompt": item["prompt"],
                "difficulty": item["difficulty"],
            }
            for item in attempt.practical_questions
        ],
        "mcq_answers": attempt.mcq_answers or {},
        "practical_answers": attempt.practical_answers or [],
        "mcq_stars": round(float(attempt.mcq_stars or 0), 2),
        "practical_stars": round(float(attempt.practical_stars or 0), 2),
        "total_stars": round(float(attempt.total_stars or 0), 2),
        "review_mode": attempt.review_mode,
        "review_notes": attempt.review_notes,
        "is_public": bool(attempt.is_public),
        "created_at": serialize_datetime(attempt.created_at),
        "submitted_at": serialize_datetime(attempt.submitted_at),
        "reviewed_at": serialize_datetime(attempt.reviewed_at),
    }
