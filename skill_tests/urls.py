from django.urls import path

from .views import (
    FreelancerSkillSelectionView,
    RatePracticalAnswerView,
    SkillCatalogView,
    SkillTestReviewView,
    SkillTestStartView,
    SkillTestSubmitView,
    ViewPublicPracticalAnswersView,
)


urlpatterns = [
    path("catalog/", SkillCatalogView.as_view(), name="skill-tests-catalog"),
    path("me/", FreelancerSkillSelectionView.as_view(), name="skill-tests-me"),
    path("select/", FreelancerSkillSelectionView.as_view(), name="skill-tests-select"),
    path("<slug:skill_slug>/start/", SkillTestStartView.as_view(), name="skill-tests-start"),
    path("<slug:skill_slug>/submit/", SkillTestSubmitView.as_view(), name="skill-tests-submit"),
    path("<slug:skill_slug>/public-practicals/", ViewPublicPracticalAnswersView.as_view(), name="skill-tests-public-practicals"),
    path("reviews/<str:attempt_id>/", SkillTestReviewView.as_view(), name="skill-tests-review"),
    path("rate-practical/<str:attempt_id>/", RatePracticalAnswerView.as_view(), name="skill-tests-rate-practical"),
]
