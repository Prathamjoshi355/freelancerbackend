
from django.urls import path, include
from accounts.views import UserCreateView, UserDetailView, google_login_callback , validation_Google_token, api_view
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.urls import path
from accounts.views import MyTokenObtainPairView

from django.http import HttpResponse

def home(request):
    return HttpResponse(" Welcome to the Freelancer Backend API")
    
urlpatterns = [
    path('', home),
    path('api/login/',api_view,name='api_login'),  
    path('api/token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    
    path('api/accounts/register/', UserCreateView.as_view(), name='account-create'),
    path('api/accounts/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/accounts/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/accounts/user/', UserDetailView.as_view(), name='user-detail'),
    path('api/accounts/validate-google-token/', validation_Google_token, name='validate_token'),
    
    # Include app URLs
    path('api/jobs/', include('jobs.urls')),
    path('api/proposals/', include('proposals.urls')),
    path('api/payments/', include('payments.urls')),
    path('api/chat/', include('chat.urls')),
    path('api/notifications/', include('notifications.urls')),
    path('api/profiles/', include('profiles.urls')),
    
    # Legacy auth URLs
    path('accounts-auth/', include('rest_framework.urls')),
    path('accounts/', include('django.contrib.auth.urls')),
    path('accounts/allauth/', include('allauth.urls')),
    path('callback/', google_login_callback, name='callback'),
]

