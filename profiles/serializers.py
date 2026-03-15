from rest_framework import serializers
from .models import Profile, SkillTest


class ProfileSerializer(serializers.Serializer):
    """Serializer for Profile model"""
    id = serializers.CharField(read_only=True)
    user_id = serializers.CharField()
    
    bio = serializers.CharField(required=False, allow_blank=True)
    avatar = serializers.CharField(required=False, allow_blank=True)
    phone = serializers.CharField(required=False, allow_blank=True)
    address = serializers.CharField(required=False, allow_blank=True)
    city = serializers.CharField(required=False, allow_blank=True)
    country = serializers.CharField(required=False, allow_blank=True)
    
    skills = serializers.ListField(child=serializers.CharField(), required=False)
    rating = serializers.FloatField(read_only=True)
    total_projects = serializers.IntegerField(read_only=True)
    hourly_rate = serializers.FloatField(required=False)
    profile_completed = serializers.BooleanField(required=False)
    
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    
    def create(self, validated_data):
        profile = Profile(**validated_data)
        profile.save()
        return profile
    
    def update(self, instance, validated_data):
        for field, value in validated_data.items():
            setattr(instance, field, value)
        instance.save()
        return instance


class SkillTestSerializer(serializers.Serializer):
    """Serializer for SkillTest model"""
    id = serializers.CharField(read_only=True)
    user_id = serializers.CharField()
    skill = serializers.CharField()
    score = serializers.FloatField(required=False)
    passed = serializers.BooleanField(read_only=True)
    completed_at = serializers.DateTimeField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)

