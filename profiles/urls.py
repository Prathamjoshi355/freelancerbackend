from django.urls import path
from .api_views import ProfileDetailView, SkillTestView

urlpatterns = [
    path('me/', ProfileDetailView.as_view(), name='profile-detail'),
    path('tests/', SkillTestView.as_view(), name='skill-tests'),
    path('tests/<str:skill>/', SkillTestView.as_view(), name='skill-test-detail'),
]

