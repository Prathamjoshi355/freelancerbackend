from django.urls import path

from .views import FreelancerDirectoryView, ProfileMeView


urlpatterns = [
    path("me/", ProfileMeView.as_view(), name="profiles-me"),
    path("freelancers/", FreelancerDirectoryView.as_view(), name="profiles-freelancers"),
]
