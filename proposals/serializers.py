from rest_framework import serializers
from .models import Proposal


class ProposalSerializer(serializers.Serializer):
    """Serializer for Proposal model"""
    id = serializers.CharField(read_only=True)
    job_id = serializers.CharField()
    freelancer_id = serializers.CharField()
    cover_letter = serializers.CharField()
    proposed_amount = serializers.FloatField()
    proposed_timeline = serializers.CharField()
    status = serializers.ChoiceField(choices=['pending', 'accepted', 'rejected', 'withdrew'])
    rating = serializers.FloatField(required=False, allow_null=True)
    completed = serializers.BooleanField(default=False)
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    
    def create(self, validated_data):
        proposal = Proposal(**validated_data)
        proposal.save()
        return proposal
    
    def update(self, instance, validated_data):
        for field, value in validated_data.items():
            setattr(instance, field, value)
        instance.save()
        return instance


class ProposalDetailSerializer(ProposalSerializer):
    """Detailed proposal with freelancer info"""
    freelancer_info = serializers.SerializerMethodField()
    job_info = serializers.SerializerMethodField()
    
    def get_freelancer_info(self, obj):
        from profiles.models import Profile
        try:
            freelancer = obj.freelancer_id
            profile = Profile.objects.filter(user_id=freelancer).first()
            return {
                'id': str(freelancer.id),
                'email': freelancer.email,
                'full_name': freelancer.full_name,
                'skills': profile.skills if profile else [],
                'rating': profile.rating if profile else 0,
            }
        except:
            return None
    
    def get_job_info(self, obj):
        return {
            'id': str(obj.job_id.id),
            'title': obj.job_id.title,
            'category': obj.job_id.category,
            'budget_min': obj.job_id.budget_min,
            'budget_max': obj.job_id.budget_max,
        }
