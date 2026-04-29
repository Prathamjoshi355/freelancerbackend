from django.urls import path

from .views import ChatProtectionAnalyzeView, ContractConversationView, ContractMessageView


urlpatterns = [
    path("protection/analyze/", ChatProtectionAnalyzeView.as_view(), name="chat-protection-analyze"),
    path("contracts/<str:contract_id>/", ContractConversationView.as_view(), name="chat-contract"),
    path("contracts/<str:contract_id>/messages/", ContractMessageView.as_view(), name="chat-messages"),
]
