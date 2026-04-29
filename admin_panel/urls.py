from django.urls import path

from .views import (
    AdminStatsView,
    AdminUsersView,
    AdminJobsView,
    AdminTransactionsView,
    AdminSkillTestsView,
)

urlpatterns = [
    path("stats/", AdminStatsView.as_view(), name="admin-stats"),
    path("users/", AdminUsersView.as_view(), name="admin-users"),
    path("jobs/", AdminJobsView.as_view(), name="admin-jobs"),
    path("transactions/", AdminTransactionsView.as_view(), name="admin-transactions"),
    path("skill-tests/", AdminSkillTestsView.as_view(), name="admin-skill-tests"),
]
