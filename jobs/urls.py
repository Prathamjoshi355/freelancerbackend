from django.urls import path

from .views import (
    ContractClientFeedbackView,
    ContractCompleteView,
    ContractDetailView,
    ContractListView,
    JobDetailView,
    JobListCreateView,
    MyJobsView,
)


urlpatterns = [
    path("", JobListCreateView.as_view(), name="jobs-list-create"),
    path("my/", MyJobsView.as_view(), name="jobs-my"),
    path("contracts/", ContractListView.as_view(), name="contracts-list"),
    path("contracts/<str:contract_id>/", ContractDetailView.as_view(), name="contracts-detail"),
    path("contracts/<str:contract_id>/complete/", ContractCompleteView.as_view(), name="contracts-complete"),
    path("contracts/<str:contract_id>/client-feedback/", ContractClientFeedbackView.as_view(), name="contracts-client-feedback"),
    path("<str:job_id>/", JobDetailView.as_view(), name="jobs-detail"),
]
