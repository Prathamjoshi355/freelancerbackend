from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import FaceLoginVerifyView, MarketplaceTokenView, MeView, RegisterView


urlpatterns = [
    path("register/", RegisterView.as_view(), name="accounts-register"),
    path("token/", MarketplaceTokenView.as_view(), name="accounts-token"),
    path("token/refresh/", TokenRefreshView.as_view(), name="accounts-token-refresh"),
    path("me/", MeView.as_view(), name="accounts-me"),
    path("face-verify/", FaceLoginVerifyView.as_view(), name="accounts-face-verify"),
]
