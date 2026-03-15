from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import TransactionViewSet, PayoutViewSet

router = DefaultRouter()
router.register(r'transactions', TransactionViewSet, basename='transaction')
router.register(r'payouts', PayoutViewSet, basename='payout')

urlpatterns = [] + router.urls
