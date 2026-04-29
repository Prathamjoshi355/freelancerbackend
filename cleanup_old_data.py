#!/usr/bin/env python
"""Cleanup script to remove old skill test data from MongoDB"""
import os
import sys
import django

# Add the backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'freelancerbackend'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'FreelancerBackend.settings')
django.setup()

from skill_tests.models import FreelancerSkill, SkillTestAttempt, PracticalAnswerRating

print(f"📊 Current state:")
print(f"  - FreelancerSkill records: {FreelancerSkill.objects.count()}")
print(f"  - SkillTestAttempt records: {SkillTestAttempt.objects.count()}")
print(f"  - PracticalAnswerRating records: {PracticalAnswerRating.objects.count()}")

print("\n🗑️  Deleting old skill test data...")
FreelancerSkill.objects.delete()
SkillTestAttempt.objects.delete()
PracticalAnswerRating.objects.delete()

print(f"\n✅ After cleanup:")
print(f"  - FreelancerSkill records: {FreelancerSkill.objects.count()}")
print(f"  - SkillTestAttempt records: {SkillTestAttempt.objects.count()}")
print(f"  - PracticalAnswerRating records: {PracticalAnswerRating.objects.count()}")
print("\n✅ All old skill test data cleared successfully!")
