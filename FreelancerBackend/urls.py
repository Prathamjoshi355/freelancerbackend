from django.http import JsonResponse
from django.urls import include, path


def home(request):
    return JsonResponse({"service": "controlled-freelance-marketplace", "status": "ok"})


def health_check(request):
    """Health check endpoint for Docker/Kubernetes"""
    return JsonResponse({"status": "healthy", "service": "backend"})


urlpatterns = [
    path("", home),
    path("api/health/", health_check),
    path("api/accounts/", include("accounts.urls")),
    path("api/profiles/", include("profiles.urls")),
    path("api/skill-tests/", include("skill_tests.urls")),
    path("api/jobs/", include("jobs.urls")),
    path("api/bids/", include("bidding.urls")),
    path("api/chat/", include("chat.urls")),
    path("api/payments/", include("payments.urls")),
    path("api/admin/", include("admin_panel.urls")),
]
