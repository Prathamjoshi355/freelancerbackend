from django.urls import path

from .views import PaymentCreateOrderView, PaymentListView, PaymentVerifyView


urlpatterns = [
    path("", PaymentListView.as_view(), name="payments-list"),
    path("contracts/<str:contract_id>/create-order/", PaymentCreateOrderView.as_view(), name="payments-create-order"),
    path("<str:payment_id>/verify/", PaymentVerifyView.as_view(), name="payments-verify"),
]
