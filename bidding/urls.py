from django.urls import path

from .views import BidActionView, BidListCreateView


urlpatterns = [
    path("", BidListCreateView.as_view(), name="bids-list-create"),
    path("<str:bid_id>/<str:action>/", BidActionView.as_view(), name="bids-action"),
]
