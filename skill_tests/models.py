from datetime import datetime

from mongoengine import (
    BooleanField,
    DateTimeField,
    DictField,
    Document,
    FloatField,
    IntField,
    ListField,
    ReferenceField,
    StringField,
)

from accounts.models import CustomUser


class Skill(Document):
    meta = {
        "collection": "skills",
        "indexes": [{"fields": ["slug"], "unique": True}, "category", "is_active"],
    }

    slug = StringField(required=True, unique=True)
    name = StringField(required=True)
    category = StringField(required=True)
    description = StringField(required=True)
    is_active = BooleanField(default=True)
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)


class SkillQuestion(Document):
    meta = {
        "collection": "skill_questions",
        "indexes": [{"fields": ["external_id"], "unique": True}, "skill", "question_type", "difficulty"],
    }

    skill = ReferenceField(Skill, required=True)
    external_id = StringField(required=True, unique=True)
    question_type = StringField(required=True, choices=["mcq", "practical"])
    difficulty = StringField(required=True, choices=["beginner", "intermediate", "advanced"])
    prompt = StringField(required=True)
    options = ListField(StringField())
    correct_answer = StringField()
    rubric_keywords = ListField(StringField())
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)


class FreelancerSkill(Document):
    meta = {
        "collection": "freelancer_skills",
        "indexes": [{"fields": ["user", "skill"], "unique": True}, "test_status"],
    }

    user = ReferenceField(CustomUser, required=True)
    skill = ReferenceField(Skill, required=True)
    test_status = StringField(
        default="not_started",
        choices=["not_started", "in_progress", "completed"],
    )
    mcq_stars = FloatField(default=0.0)  # 0-7 stars
    practical_stars = FloatField(default=0.0)  # 0-3 stars from peer ratings
    total_stars = FloatField(default=0.0)  # 0-10 stars
    attempts = IntField(default=0)
    review_mode = StringField(default="auto")
    review_notes = StringField()
    selected_at = DateTimeField(default=datetime.utcnow)
    reviewed_at = DateTimeField()
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)


class SkillTestAttempt(Document):
    meta = {
        "collection": "skill_test_attempts",
        "indexes": ["user", "skill", "status", "created_at"],
    }

    user = ReferenceField(CustomUser, required=True)
    skill = ReferenceField(Skill, required=True)
    status = StringField(
        default="started",
        choices=["started", "completed"],
    )
    mcq_questions = ListField(DictField())
    practical_questions = ListField(DictField())
    mcq_answers = DictField()
    practical_answers = ListField(DictField())
    mcq_stars = FloatField(default=0.0)  # 0-7 stars (based on % correct)
    practical_stars = FloatField(default=0.0)  # 0-3 stars (average peer rating)
    total_stars = FloatField(default=0.0)  # 0-10 stars
    review_mode = StringField(default="auto")
    review_notes = StringField()
    is_public = BooleanField(default=True)  # Practical answers visible to others
    created_at = DateTimeField(default=datetime.utcnow)
    submitted_at = DateTimeField()
    reviewed_at = DateTimeField()
    updated_at = DateTimeField(default=datetime.utcnow)

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)


class PracticalAnswerRating(Document):
    """Freelancers rate each other's practical answers out of 3"""
    meta = {
        "collection": "practical_answer_ratings",
        "indexes": [
            {"fields": ["attempt", "reviewer"], "unique": True},
            "attempt",
            "reviewer",
            "created_at",
        ],
    }

    attempt = ReferenceField(SkillTestAttempt, required=True)
    reviewer = ReferenceField(CustomUser, required=True)  # Freelancer doing the rating
    stars = FloatField(required=True, min_value=0, max_value=3)  # Scale: 0-3 stars
    comment = StringField()
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)
