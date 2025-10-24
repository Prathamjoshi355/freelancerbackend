
from django.contrib import admin
from django.urls import path, include
from accounts.views import UserCreateView, UserDetailView, google_login_callback , validation_Google_token, api_view
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.urls import path
from accounts.views import MyTokenObtainPairView

from django.contrib import admin

# from django.urls import path, include
from django.http import HttpResponse
# from django.urls import path

def home(request):
    return HttpResponse(" Welcome to the Freelancer Backend API")
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home),
    path ('api/login/',api_view,name='api_login'),  
    path('login/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    
    # path('accounts/register/', register_user, name='register_user'),
    # path('user/register/', RegisterView.as_view(), name='register'),
    # path('accounts/user/registerform/',UserRegisterView.as_view, name='register_user'),
    path('accounts/user/register/',UserCreateView.as_view(),name='account-create'),
    path('accounts/token', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('accounts/token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('accounts-auth/', include('rest_framework.urls')),
    path('accounts/', include('django.contrib.auth.urls')),
    path('accounts/allauth/', include('allauth.urls')),
    path('callback/', google_login_callback, name='callback'),
    path('accounts/user/', UserDetailView.as_view(), name='user-detail'),
    path('accounts/validate-google-token/', validation_Google_token, name='validate_token'),
]

