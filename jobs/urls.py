from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import JobViewSet, ApplyJobView, MyJobsView, MyApplicationsView

router = DefaultRouter()
router.register(r'', JobViewSet, basename='job')

urlpatterns = [
    path('apply/', ApplyJobView.as_view(), name='apply-job'),
    path('my-jobs/', MyJobsView.as_view(), name='my-jobs'),
    path('my-applications/', MyApplicationsView.as_view(), name='my-applications'),
] + router.urls
