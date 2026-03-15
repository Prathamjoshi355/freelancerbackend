from rest_framework import serializers
from .models import Job, JobApplication


class JobSerializer(serializers.Serializer):
    """Serializer for Job model"""
    id = serializers.CharField(read_only=True)
    client_id = serializers.CharField()
    title = serializers.CharField(max_length=200)
    description = serializers.CharField()
    category = serializers.CharField(max_length=100)
    
    budget_type = serializers.ChoiceField(choices=['fixed', 'hourly'])
    budget_min = serializers.FloatField()
    budget_max = serializers.FloatField()
    hourly_rate = serializers.FloatField(required=False, allow_null=True)
    
    duration = serializers.ChoiceField(choices=['short', 'medium', 'long'])
    required_skills = serializers.ListField(child=serializers.CharField())
    experience_level = serializers.ChoiceField(choices=['beginner', 'intermediate', 'expert'])
    
    status = serializers.ChoiceField(choices=['open', 'in_progress', 'completed', 'closed'])
    is_featured = serializers.BooleanField(default=False)
    views_count = serializers.IntegerField(default=0)
    proposals_count = serializers.IntegerField(default=0)
    
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    deadline = serializers.DateTimeField()
    
    def create(self, validated_data):
        job = Job(**validated_data)
        job.save()
        return job
    
    def update(self, instance, validated_data):
        for field, value in validated_data.items():
            setattr(instance, field, value)
        instance.save()
        return instance


class JobApplicationSerializer(serializers.Serializer):
    """Serializer for Job Application"""
    id = serializers.CharField(read_only=True)
    job_id = serializers.CharField()
    freelancer_id = serializers.CharField()
    status = serializers.ChoiceField(choices=['pending', 'accepted', 'rejected'])
    applied_at = serializers.DateTimeField(read_only=True)


class JobDetailSerializer(JobSerializer):
    """Detailed job info with client details"""
    client_info = serializers.SerializerMethodField()
    
    def get_client_info(self, obj):
        from accounts.models import CustomUser
        try:
            client = CustomUser.objects.get(id=obj.client_id.id)
            return {
                'id': str(client.id),
                'email': client.email,
                'company_name': client.company_name
            }
        except:
            return None
