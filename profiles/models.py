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


class Profile(Document):
    meta = {
        "collection": "profiles",
        "indexes": [
            {"fields": ["user"], "unique": True},
            "role",
            "is_complete",
            "selected_skill_slugs",
            "username",
            "city",
            "country",
            "categories",
        ],
    }

    user = ReferenceField(CustomUser, required=True, unique=True)
    role = StringField(required=True, choices=CustomUser.ROLE_CHOICES)

    full_name = StringField(max_length=120)
    profile_photo_url = StringField()
    company_name = StringField(max_length=160)
    city = StringField(max_length=80)
    country = StringField(max_length=80)

    industry = StringField(max_length=120)
    company_size = StringField(max_length=80)
    description = StringField()
    internal_contact_info = StringField()
    preferred_communication_method = StringField(default="platform_chat")
    typical_response_time_hours = IntField()

    username = StringField(max_length=50)
    timezone = StringField(max_length=80)
    languages_spoken = ListField(StringField(), default=list)
    professional_title = StringField(max_length=160)
    bio = StringField()
    experience_level = StringField(choices=["entry", "intermediate", "expert"])
    years_of_experience = IntField(min_value=0)
    categories = ListField(StringField(), default=list)
    portfolio_url = StringField()
    portfolio_items = ListField(DictField(), default=list)
    selected_skill_slugs = ListField(StringField())
    hourly_rate = FloatField(min_value=0)
    fixed_project_rate = FloatField(min_value=0)
    availability = StringField(choices=["full_time", "part_time", "not_available"])
    working_hours = StringField(max_length=120)

    work_history = ListField(DictField(), default=list)
    education = ListField(DictField(), default=list)
    certifications = ListField(DictField(), default=list)

    github_url = StringField()
    linkedin_url = StringField()
    website_url = StringField()

    phone_verified = BooleanField(default=False)
    identity_verified = BooleanField(default=False)

    initial_rating = FloatField(default=0.0)
    final_rating = FloatField(default=0.0)
    overall_rating = FloatField(default=0.0)
    total_reviews = IntField(default=0)
    total_completed_jobs = IntField(default=0)

    is_complete = BooleanField(default=False)
    completion_percentage = IntField(default=0)
    missing_requirements = ListField(StringField())

    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.email} profile"
