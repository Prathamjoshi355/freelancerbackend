import random
from datetime import datetime

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.policies import (
    compute_final_rating,
    compute_initial_rating,
    ensure_freelancer_profile_complete,
    get_completed_job_ratings,
    get_or_create_profile,
    sync_profile_completion,
)
from .models import Profile, SkillTest
from .serializers import ProfileSerializer, SkillTestSerializer


QUESTION_BANK = {
    "javascript": {
        "beginner": [{"id": f"js-b-{i}", "question": f"JavaScript beginner question {i}", "type": "mcq"} for i in range(1, 31)],
        "intermediate": [{"id": f"js-i-{i}", "question": f"JavaScript intermediate question {i}", "type": "mcq"} for i in range(1, 31)],
        "hard": [{"id": f"js-h-{i}", "question": f"JavaScript hard question {i}", "type": "mcq"} for i in range(1, 21)],
        "practical": [{"id": f"js-p-{i}", "question": f"JavaScript practical task {i}", "type": "practical"} for i in range(1, 11)],
    },
    "react": {
        "beginner": [{"id": f"react-b-{i}", "question": f"React beginner question {i}", "type": "mcq"} for i in range(1, 31)],
        "intermediate": [{"id": f"react-i-{i}", "question": f"React intermediate question {i}", "type": "mcq"} for i in range(1, 31)],
        "hard": [{"id": f"react-h-{i}", "question": f"React hard question {i}", "type": "mcq"} for i in range(1, 21)],
        "practical": [{"id": f"react-p-{i}", "question": f"React practical task {i}", "type": "practical"} for i in range(1, 11)],
    },
    "python": {
        "beginner": [{"id": f"py-b-{i}", "question": f"Python beginner question {i}", "type": "mcq"} for i in range(1, 31)],
        "intermediate": [{"id": f"py-i-{i}", "question": f"Python intermediate question {i}", "type": "mcq"} for i in range(1, 31)],
        "hard": [{"id": f"py-h-{i}", "question": f"Python hard question {i}", "type": "mcq"} for i in range(1, 21)],
        "practical": [{"id": f"py-p-{i}", "question": f"Python practical task {i}", "type": "practical"} for i in range(1, 11)],
    },
}


def build_skill_test_payload(skills):
    rng = random.SystemRandom()
    normalized_skills = [skill.strip().lower() for skill in skills if skill.strip()]
    if not normalized_skills:
        return {"mcq_questions": [], "practical_questions": []}

    mcq_questions = []
    practical_questions = []
    used_ids = set()

    for difficulty, count in (("beginner", 20), ("intermediate", 20), ("hard", 10)):
        pool = []
        for skill in normalized_skills:
            bank = QUESTION_BANK.get(skill, QUESTION_BANK["javascript"])
            pool.extend([{**item, "skill": skill} for item in bank[difficulty]])
        unique_pool = [item for item in pool if item["id"] not in used_ids]
        selected = rng.sample(unique_pool, min(count, len(unique_pool)))
        used_ids.update(item["id"] for item in selected)
        mcq_questions.extend(selected)

    for skill in normalized_skills:
        bank = QUESTION_BANK.get(skill, QUESTION_BANK["javascript"])
        selected = rng.sample(bank["practical"], min(2, len(bank["practical"])))
        practical_questions.extend([{**item, "skill": skill} for item in selected])

    return {
        "mcq_questions": mcq_questions[:50],
        "practical_questions": practical_questions,
    }


class ProfileDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile = get_or_create_profile(request.user)
        if request.user.role == 'freelancer' and not profile.full_name:
            profile.full_name = request.user.full_name
        sync_profile_completion(profile)
        profile.save()
        serializer = ProfileSerializer(profile)
        return Response({
            **serializer.data,
            'id': str(profile.id),
            'user_id': str(profile.user_id.id),
        }, status=status.HTTP_200_OK)

    def post(self, request):
        return self.put(request)

    def put(self, request):
        profile = get_or_create_profile(request.user)
        data = request.data.copy()
        data.pop('user_id', None)
        if request.user.role == 'freelancer' and not data.get('full_name'):
            data['full_name'] = request.user.full_name
        serializer = ProfileSerializer(profile, data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        updated_profile = serializer.save()
        return Response({
            'message': 'Profile updated successfully',
            **ProfileSerializer(updated_profile).data,
            'id': str(updated_profile.id),
            'user_id': str(updated_profile.user_id.id),
        }, status=status.HTTP_200_OK)


class SkillTestView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, skill=None):
        ensure_freelancer_profile_complete(request.user)
        profile = get_or_create_profile(request.user)
        if skill:
            test = SkillTest.objects(user_id=request.user, skill=skill).first()
            if test:
                return Response({**SkillTestSerializer(test).data, 'id': str(test.id)})
            generated = build_skill_test_payload([skill])
            return Response({
                'skill': skill,
                **generated,
                'generated_from_profile_skills': profile.skills,
            })

        generated = build_skill_test_payload(profile.skills)
        tests = SkillTest.objects(user_id=request.user)
        return Response({
            'skills': profile.skills,
            'generated_test': generated,
            'results': [{**SkillTestSerializer(test).data, 'id': str(test.id)} for test in tests],
        })

    def post(self, request):
        ensure_freelancer_profile_complete(request.user)
        profile = get_or_create_profile(request.user)
        profile_skills = set(skill.lower() for skill in profile.skills)
        skill = (request.data.get('skill') or '').strip()
        if not skill or skill.lower() not in profile_skills:
            return Response({'detail': 'Skill test must match a skill from the profile.'}, status=status.HTTP_400_BAD_REQUEST)

        mcq_score = float(request.data.get('mcq_score', 0))
        practical_score = float(request.data.get('practical_score', 0))
        initial_rating = compute_initial_rating(mcq_score, practical_score)
        final_rating = compute_final_rating(initial_rating, get_completed_job_ratings(request.user))

        test = SkillTest.objects(user_id=request.user, skill=skill).first()
        if not test:
            test = SkillTest(user_id=request.user, skill=skill)

        test.mcq_score = mcq_score
        test.practical_score = practical_score
        test.score = initial_rating
        test.passed = initial_rating >= 70
        test.profile_snapshot_skills = profile.skills
        test.mcq_questions = request.data.get('mcq_questions', [])
        test.practical_questions = request.data.get('practical_questions', [])
        test.completed_at = datetime.utcnow()
        test.save()

        profile.initial_rating = initial_rating
        profile.final_rating = final_rating
        profile.rating = final_rating
        profile.save()

        return Response({
            'message': 'Skill test recorded',
            'initial_rating': initial_rating,
            'final_rating': final_rating,
            **SkillTestSerializer(test).data,
            'id': str(test.id),
        }, status=status.HTTP_200_OK)
