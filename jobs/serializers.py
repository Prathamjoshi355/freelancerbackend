from rest_framework import serializers

from core.policies import serialize_datetime


class JobInputSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=200)
    description = serializers.CharField()
    budget_min = serializers.FloatField(min_value=0)
    budget_max = serializers.FloatField(min_value=0)
    required_skill_slugs = serializers.ListField(child=serializers.CharField(), allow_empty=False)

    def validate(self, attrs):
        if attrs["budget_max"] < attrs["budget_min"]:
            raise serializers.ValidationError({"budget_max": "budget_max must be greater than or equal to budget_min."})
        return attrs


class ContractCompletionSerializer(serializers.Serializer):
    rating = serializers.IntegerField(min_value=1, max_value=5)
    comment = serializers.CharField(required=False, allow_blank=True)


class FreelancerClientFeedbackSerializer(serializers.Serializer):
    client_rating = serializers.IntegerField(min_value=1, max_value=5)
    client_comment = serializers.CharField(required=False, allow_blank=True)


def serialize_job(job):
    from core.policies import get_or_create_profile
    from profiles.serializers import serialize_profile_summary

    return {
        "id": str(job.id),
        "client_id": str(job.client.id),
        "title": job.title,
        "description": job.description,
        "budget_min": round(float(job.budget_min or 0), 2),
        "budget_max": round(float(job.budget_max or 0), 2),
        "required_skill_slugs": job.required_skill_slugs or [],
        "status": job.status,
        "hired_freelancer_id": str(job.hired_freelancer.id) if job.hired_freelancer else None,
        "hired_bid_id": job.hired_bid_id,
        "bid_count": int(job.bid_count or 0),
        "client_profile": serialize_profile_summary(get_or_create_profile(job.client)),
        "created_at": serialize_datetime(job.created_at),
        "updated_at": serialize_datetime(job.updated_at),
    }


def serialize_contract(contract):
    from core.policies import get_or_create_profile
    from profiles.serializers import serialize_profile_summary

    return {
        "id": str(contract.id),
        "job_id": str(contract.job.id),
        "client_id": str(contract.client.id),
        "freelancer_id": str(contract.freelancer.id),
        "bid_id": contract.bid_id,
        "agreed_amount": round(float(contract.agreed_amount or 0), 2),
        "status": contract.status,
        "payment_status": contract.payment_status,
        "client_profile": serialize_profile_summary(get_or_create_profile(contract.client)),
        "freelancer_profile": serialize_profile_summary(get_or_create_profile(contract.freelancer)),
        "created_at": serialize_datetime(contract.created_at),
        "updated_at": serialize_datetime(contract.updated_at),
        "completed_at": serialize_datetime(contract.completed_at),
    }


def serialize_review(review):
    return {
        "id": str(review.id),
        "contract_id": str(review.contract.id),
        "job_id": str(review.job.id),
        "client_id": str(review.client.id),
        "freelancer_id": str(review.freelancer.id),
        "rating": int(review.rating),
        "comment": review.comment,
        "client_rating": int(review.client_rating or 0) if review.client_rating else None,
        "client_comment": review.client_comment or "",
        "client_reviewed_at": serialize_datetime(review.client_reviewed_at),
        "created_at": serialize_datetime(review.created_at),
    }
