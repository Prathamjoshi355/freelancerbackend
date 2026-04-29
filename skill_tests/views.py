import random
from datetime import datetime

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.env import get_env
from core.policies import (
    compute_skill_rating,
    get_or_create_profile,
    require_profile_complete,
    sync_user_account_status,
    update_freelancer_ratings,
)
from .catalog import SKILL_BLUEPRINTS
from .models import FreelancerSkill, Skill, SkillQuestion, SkillTestAttempt
from .serializers import (
    SkillReviewSerializer,
    SkillSelectionSerializer,
    SkillSubmissionSerializer,
    serialize_attempt,
    serialize_freelancer_skill,
    serialize_skill,
)


QUESTION_TEMPLATES = [
    ("beginner", "What is the primary purpose of {term} in {skill} work?", "purpose"),
    ("beginner", "When should a specialist use {term} in a real {skill} project?", "scenario"),
    ("beginner", "Which statement best fits {term} in day-to-day {skill} delivery?", "best_practice"),
    ("intermediate", "Which risk best describes misusing {term} in {skill}?", "tradeoff"),
    ("intermediate", "Which option most accurately explains {term} for a working {skill} team?", "purpose"),
    ("intermediate", "Which scenario is the strongest fit for {term} in {skill}?", "scenario"),
    ("advanced", "Which statement about {term} is correct for production-grade {skill} work?", "best_practice"),
    ("advanced", "Which trade-off is most associated with {term} in {skill} systems?", "tradeoff"),
]


def ensure_catalog_seeded():
    for slug, blueprint in SKILL_BLUEPRINTS.items():
        skill = Skill.objects(slug=slug).first()
        if skill is None:
            skill = Skill(slug=slug)
        skill.name = blueprint["name"]
        skill.category = blueprint["category"]
        skill.description = blueprint["description"]
        skill.is_active = True
        skill.save()

        for concept_index, concept in enumerate(blueprint["concepts"], start=1):
            for question_index, (difficulty, template, answer_key) in enumerate(QUESTION_TEMPLATES, start=1):
                external_id = f"{slug}-mcq-{concept_index}-{question_index}"
                question = SkillQuestion.objects(external_id=external_id).first() or SkillQuestion(external_id=external_id)
                question.skill = skill
                question.question_type = "mcq"
                question.difficulty = difficulty
                question.prompt = template.format(term=concept["term"], skill=skill.name)
                question.correct_answer = concept[answer_key]
                question.options = [concept[answer_key], *concept["distractors"]]
                question.save()

        for prompt_index, prompt in enumerate(blueprint["practical"], start=1):
            external_id = f"{slug}-practical-{prompt_index}"
            question = SkillQuestion.objects(external_id=external_id).first() or SkillQuestion(external_id=external_id)
            question.skill = skill
            question.question_type = "practical"
            question.difficulty = "advanced"
            question.prompt = prompt["prompt"]
            question.options = []
            question.correct_answer = ""
            question.rubric_keywords = prompt["keywords"]
            question.save()


def score_practical(practical_questions, practical_answers):
    answers_by_id = {
        str(item.get("question_id")): str(item.get("answer") or "").lower() for item in practical_answers
    }
    scores = []
    for question in practical_questions:
        answer = answers_by_id.get(question["id"], "")
        keywords = [keyword.lower() for keyword in question.get("rubric_keywords", [])]
        keyword_hits = sum(1 for keyword in keywords if keyword in answer)
        keyword_score = (keyword_hits / max(len(keywords), 1)) * 80
        length_score = min(len(answer) / 400, 1) * 20
        scores.append(keyword_score + length_score)
    if not scores:
        return 0.0
    return round(sum(scores) / len(scores), 2)


class SkillCatalogView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ensure_catalog_seeded()
        skills = Skill.objects(is_active=True).order_by("name")
        return Response({"results": [serialize_skill(skill) for skill in skills]})


class FreelancerSkillSelectionView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != "freelancer":
            return Response({"detail": "Only freelancers have skill tests."}, status=status.HTTP_403_FORBIDDEN)
        ensure_catalog_seeded()
        profile = get_or_create_profile(request.user)
        mappings = FreelancerSkill.objects(user=request.user)
        return Response(
            {
                "selected_skill_slugs": profile.selected_skill_slugs or [],
                "results": [serialize_freelancer_skill(mapping) for mapping in mappings],
            }
        )

    def post(self, request):
        if request.user.role != "freelancer":
            return Response({"detail": "Only freelancers can select skills."}, status=status.HTTP_403_FORBIDDEN)

        require_profile_complete(request.user)
        ensure_catalog_seeded()
        serializer = SkillSelectionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        normalized = sorted({slug.strip().lower() for slug in serializer.validated_data["skill_slugs"] if slug.strip()})
        skills = list(Skill.objects(slug__in=normalized, is_active=True))
        if len(skills) != len(normalized):
            known_slugs = {skill.slug for skill in skills}
            unknown = sorted(set(normalized) - known_slugs)
            return Response({"detail": f"Unknown skills requested: {', '.join(unknown)}"}, status=status.HTTP_400_BAD_REQUEST)

        current_mappings = list(FreelancerSkill.objects(user=request.user))
        current_by_slug = {mapping.skill.slug: mapping for mapping in current_mappings}
        requested_slugs = set(normalized)
        for mapping in current_mappings:
            if mapping.skill.slug not in requested_slugs:
                mapping.delete()

        for skill in skills:
            if skill.slug not in current_by_slug:
                FreelancerSkill(user=request.user, skill=skill).save()

        profile = get_or_create_profile(request.user)
        profile.selected_skill_slugs = normalized
        profile.save()
        sync_user_account_status(request.user)

        fresh_mappings = FreelancerSkill.objects(user=request.user)
        return Response(
            {
                "message": "Skills updated successfully.",
                "selected_skill_slugs": normalized,
                "results": [serialize_freelancer_skill(mapping) for mapping in fresh_mappings],
            }
        )


class SkillTestStartView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, skill_slug):
        if request.user.role != "freelancer":
            return Response({"detail": "Only freelancers can start tests."}, status=status.HTTP_403_FORBIDDEN)

        require_profile_complete(request.user)
        ensure_catalog_seeded()
        skill = Skill.objects(slug=skill_slug, is_active=True).first()
        mapping = FreelancerSkill.objects(user=request.user, skill=skill).first() if skill else None
        if skill is None or mapping is None:
            return Response({"detail": "Select this skill before starting its test."}, status=status.HTTP_400_BAD_REQUEST)

        existing_attempt = SkillTestAttempt.objects(user=request.user, skill=skill, status="started").first()
        if existing_attempt:
            return Response({"attempt": serialize_attempt(existing_attempt), "mapping": serialize_freelancer_skill(mapping)})

        mcq_pool = list(SkillQuestion.objects(skill=skill, question_type="mcq"))
        practical_pool = list(SkillQuestion.objects(skill=skill, question_type="practical"))
        rng = random.SystemRandom()
        mcq_questions = rng.sample(mcq_pool, min(50, len(mcq_pool)))
        practical_questions = rng.sample(practical_pool, min(2, len(practical_pool)))

        attempt = SkillTestAttempt(
            user=request.user,
            skill=skill,
            status="started",
            mcq_questions=[
                {"id": str(question.id), "prompt": question.prompt, "options": question.options, "difficulty": question.difficulty, "correct_answer": question.correct_answer}
                for question in mcq_questions
            ],
            practical_questions=[
                {"id": str(question.id), "prompt": question.prompt, "difficulty": question.difficulty, "rubric_keywords": question.rubric_keywords}
                for question in practical_questions
            ],
        )
        attempt.save()

        mapping.test_status = "in_progress"
        mapping.attempts = int(mapping.attempts or 0) + 1
        mapping.save()
        return Response({"attempt": serialize_attempt(attempt), "mapping": serialize_freelancer_skill(mapping)})


class SkillTestSubmitView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, skill_slug):
        if request.user.role != "freelancer":
            return Response({"detail": "Only freelancers can submit tests."}, status=status.HTTP_403_FORBIDDEN)

        try:
            serializer = SkillSubmissionSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"detail": f"Invalid submission: {serializer.errors}"}, status=status.HTTP_400_BAD_REQUEST)

            skill = Skill.objects(slug=skill_slug, is_active=True).first()
            mapping = FreelancerSkill.objects(user=request.user, skill=skill).first() if skill else None
            if skill is None or mapping is None:
                return Response({"detail": "Select this skill before submitting its test."}, status=status.HTTP_400_BAD_REQUEST)

            attempt = SkillTestAttempt.objects(id=serializer.validated_data["attempt_id"], user=request.user, skill=skill, status="started").first()
            if attempt is None:
                return Response({"detail": "Open test attempt not found."}, status=status.HTTP_404_NOT_FOUND)

            # ✅ ENFORCE: Must have exactly 50 MCQ and 2 practical questions
            if len(attempt.mcq_questions) != 50:
                return Response({"detail": f"Test must have exactly 50 MCQ questions. Found: {len(attempt.mcq_questions)}"}, status=status.HTTP_400_BAD_REQUEST)
            if len(attempt.practical_questions) != 2:
                return Response({"detail": f"Test must have exactly 2 practical questions. Found: {len(attempt.practical_questions)}"}, status=status.HTTP_400_BAD_REQUEST)

            mcq_answers = serializer.validated_data["mcq_answers"]
            practical_answers = serializer.validated_data.get("practical_answers", [])

            # ✅ Count correct MCQ answers
            correct_count = 0
            for question in attempt.mcq_questions:
                submitted = str(mcq_answers.get(question["id"], "")).strip()
                if submitted == question["correct_answer"]:
                    correct_count += 1

            # ✅ Convert MCQ score to 0-7 scale: 50 questions → 0-7 points
            mcq_stars = round((correct_count / 50) * 7, 2)  # 0-7 scale
            practical_stars = 0.0  # Admin will grade practical later, starts at 0
            total_stars = mcq_stars  # Only MCQ counts for marketplace unlock

            attempt.review_mode = "auto"
            attempt.mcq_answers = mcq_answers
            attempt.practical_answers = practical_answers  # Store for admin review
            attempt.mcq_stars = mcq_stars  # 0-7 scale
            attempt.practical_stars = practical_stars  # 0 - pending admin review
            attempt.total_stars = total_stars
            attempt.submitted_at = datetime.utcnow()
            attempt.status = "completed"  # ✅ IMMEDIATELY MARK AS COMPLETED (marketplace unlocks now)
            attempt.is_public = True

            mapping.mcq_stars = mcq_stars
            mapping.practical_stars = practical_stars
            mapping.total_stars = total_stars
            mapping.review_mode = "pending_admin_review"  # Admin will review practical later
            mapping.test_status = "completed"  # ✅ UNLOCKS MARKETPLACE IMMEDIATELY

            attempt.save()
            mapping.save()
            ratings = update_freelancer_ratings(request.user)
            sync_user_account_status(request.user)
            return Response({
                "attempt": serialize_attempt(attempt), 
                "mapping": serialize_freelancer_skill(mapping), 
                "ratings": ratings,
                "message": f"✅ Test completed! You scored {mcq_stars}/7 on MCQ. Marketplace is now unlocked! Admin will review your practical answers separately."
            })
        except Exception as e:
            return Response({"detail": f"Error submitting test: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SkillTestReviewView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, attempt_id):
        if not request.user.is_staff:
            return Response({"detail": "Only staff reviewers can score manual practical tests."}, status=status.HTTP_403_FORBIDDEN)

        serializer = SkillReviewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        attempt = SkillTestAttempt.objects(id=attempt_id, status="under_review").first()
        if attempt is None:
            return Response({"detail": "Review target not found."}, status=status.HTTP_404_NOT_FOUND)

        mapping = FreelancerSkill.objects(user=attempt.user, skill=attempt.skill).first()
        attempt.practical_score = serializer.validated_data["practical_score"]
        attempt.review_notes = serializer.validated_data.get("review_notes", "")
        attempt.overall_rating = compute_skill_rating(attempt.mcq_score, attempt.practical_score)
        attempt.passed = attempt.overall_rating >= 70
        attempt.status = "completed"
        attempt.reviewed_at = datetime.utcnow()
        attempt.save()

        if mapping:
            mapping.practical_score = attempt.practical_score
            mapping.rating = attempt.overall_rating
            mapping.review_notes = attempt.review_notes
            mapping.reviewed_at = attempt.reviewed_at
            mapping.test_status = "passed" if attempt.passed else "failed"
            mapping.save()
            update_freelancer_ratings(attempt.user)
            sync_user_account_status(attempt.user)

        return Response({"attempt": serialize_attempt(attempt), "mapping": serialize_freelancer_skill(mapping) if mapping else None})


class RatePracticalAnswerView(APIView):
    """✅ Freelancers rate others' practical answers (0-3 scale)"""
    permission_classes = [IsAuthenticated]

    def post(self, request, attempt_id):
        if request.user.role != "freelancer":
            return Response({"detail": "Only freelancers can rate practical answers."}, status=status.HTTP_403_FORBIDDEN)

        attempt = SkillTestAttempt.objects(id=attempt_id, status="completed", is_public=True).first()
        if not attempt:
            return Response({"detail": "Practical answers not found or not available for rating."}, status=status.HTTP_404_NOT_FOUND)

        # Don't rate your own work
        if attempt.user == request.user:
            return Response({"detail": "You cannot rate your own practical answers."}, status=status.HTTP_400_BAD_REQUEST)

        stars_value = request.data.get("stars")
        comment = request.data.get("comment", "").strip()

        if not isinstance(stars_value, (int, float)) or stars_value < 0 or stars_value > 3:
            return Response({"detail": "Stars rating must be between 0 and 3."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if already rated
        from .models import PracticalAnswerRating
        existing_rating = PracticalAnswerRating.objects(attempt=attempt, reviewer=request.user).first()
        if existing_rating:
            existing_rating.stars = stars_value
            existing_rating.comment = comment
            existing_rating.save()
            message = "Rating updated successfully."
        else:
            PracticalAnswerRating(
                attempt=attempt,
                reviewer=request.user,
                stars=stars_value,
                comment=comment
            ).save()
            message = "Rating submitted successfully."

        # Recalculate practical score as average of all ratings
        all_ratings = list(PracticalAnswerRating.objects(attempt=attempt))
        if all_ratings:
            avg_stars = round(sum(r.stars for r in all_ratings) / len(all_ratings), 2)
            attempt.practical_stars = avg_stars
            
            # Update total star rating (MCQ + Practical)
            attempt.total_stars = round(attempt.mcq_stars + attempt.practical_stars, 2)
            attempt.save()

            # Update freelancer mapping
            mapping = FreelancerSkill.objects(user=attempt.user, skill=attempt.skill).first()
            if mapping:
                mapping.practical_stars = avg_stars
                mapping.total_stars = round(mapping.mcq_stars + avg_stars, 2)
                mapping.save()
                update_freelancer_ratings(attempt.user)

        return Response({
            "message": message,
            "stars": stars_value,
            "average_stars": attempt.practical_stars,
            "total_stars": attempt.total_stars,
            "total_ratings": len(all_ratings)
        }, status=status.HTTP_200_OK)


class ViewPublicPracticalAnswersView(APIView):
    """✅ Freelancers can see completed practical answers of others to rate"""
    permission_classes = [IsAuthenticated]

    def get(self, request, skill_slug):
        if request.user.role != "freelancer":
            return Response({"detail": "Only freelancers can view practical answers."}, status=status.HTTP_403_FORBIDDEN)

        skill = Skill.objects(slug=skill_slug, is_active=True).first()
        if not skill:
            return Response({"detail": "Skill not found."}, status=status.HTTP_404_NOT_FOUND)

        # Get all completed, public practical answers for this skill
        attempts = SkillTestAttempt.objects(
            skill=skill,
            status="completed",
            is_public=True
        ).order_by("-practical_stars")

        results = []
        for attempt in attempts:
            # Skip own attempts
            if attempt.user == request.user:
                continue
            
            from .models import PracticalAnswerRating
            ratings = list(PracticalAnswerRating.objects(attempt=attempt))
            my_rating = next((r for r in ratings if r.reviewer == request.user), None)

            results.append({
                "attempt_id": str(attempt.id),
                "freelancer_email": attempt.user.email,
                "skill": skill_slug,
                "mcq_stars": attempt.mcq_stars,
                "practical_stars": attempt.practical_stars,
                "total_stars": attempt.total_stars,
                "total_ratings": len(ratings),
                "my_rating": my_rating.stars if my_rating else None,
                "practical_answers": attempt.practical_answers,
            })

        return Response({"results": results})
