from rest_framework import serializers

from .models import Proposal


class ProposalSerializer(serializers.Serializer):
    id = serializers.CharField(read_only=True)
    job_id = serializers.CharField()
    freelancer_id = serializers.CharField(required=False)
    cover_letter = serializers.CharField()
    proposed_amount = serializers.FloatField()
    proposed_timeline = serializers.CharField(required=False, allow_blank=True)
    status = serializers.ChoiceField(choices=['pending', 'hired', 'rejected', 'withdrew', 'auto_rejected'], required=False)
    rating = serializers.FloatField(required=False, allow_null=True)
    initial_rating = serializers.FloatField(required=False)
    job_rating = serializers.FloatField(required=False)
    final_rating = serializers.FloatField(required=False)
    completed = serializers.BooleanField(default=False, required=False)
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)


class ProposalDetailSerializer(ProposalSerializer):
    freelancer_info = serializers.SerializerMethodField()
    job_info = serializers.SerializerMethodField()

    def get_freelancer_info(self, obj):
        from profiles.models import Profile

        freelancer = obj.freelancer_id
        profile = Profile.objects.filter(user_id=freelancer).first()
        return {
            'id': str(freelancer.id),
            'email': freelancer.email,
            'full_name': freelancer.full_name,
            'skills': profile.skills if profile else [],
            'rating': profile.rating if profile else 0,
            'initial_rating': profile.initial_rating if profile else 0,
            'final_rating': profile.final_rating if profile else 0,
        }

    def get_job_info(self, obj):
        return {
            'id': str(obj.job_id.id),
            'title': obj.job_id.title,
            'category': obj.job_id.category,
            'status': obj.job_id.status,
            'budget_min': obj.job_id.budget_min,
            'budget_max': obj.job_id.budget_max,
        }
