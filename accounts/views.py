from django.shortcuts import render, redirect
# from django.contrib.auth.models import User
from .models import CustomUser
from rest_framework import viewsets ,generics
from .serializers import UserSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from allauth.socialaccount.models import SocialToken, SocialAccount
from django.contrib.auth.decorators import login_required
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from rest_framework import status
from django.views.decorators.csrf import csrf_exempt
import json
from django.contrib.auth import authenticate
# from django.contrib.auth.models import User
from rest_framework.decorators import api_view

# from rest_framework.views import APIView
from rest_framework.response import Response
# from rest_framework import status
# # from django.shortcuts import render, redirect
# from django.contrib.auth.forms import UserCreationForm
# from django.contrib import messages
# class RegisterView(APIView):
#     def post(self, request):
#         print("Incoming registration data:", request.data)  # for debugging
#         serializer = UserSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)
#         print("Serializer errors:", serializer.errors)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
user = get_user_model()
# from django.shortcuts import render, redirect
# from django.contrib.auth.forms import UserCreationForm
# from django.contrib import messages

# def register_user(request):
#     if request.method == 'POST':
#         form = UserCreationForm(request.POST)
#         if form.is_valid():
#             form.save()
#             username = form.cleaned_data.get('username')
#             messages.success(request, f'Account created for {username}!')
#             return redirect('login')  # redirect to login or homepage
#     else:
#         form = UserCreationForm()
#     return render(request, 'accounts/register.html', {'form': form})
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import MyTokenObtainPairSerializer

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

class UserCreateView(generics.CreateAPIView):
    # queryset = User.objects.all()
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]
   
    
    def get(self, request, *args, **kwargs):
        return Response({"message": "User registration endpoint is working!"}) 
    

    def post(self, request, *args, **kwargs):
        print("Incoming registration data:", request.data)
        return super().post(request, *args, **kwargs)
     
class UserDetailView(generics.RetrieveUpdateAPIView):
    queryset =  CustomUser.objects.all()
    
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]  
    # def get_object(self):
    #     # Return only the authenticated user's data
    #     return self.request.user
    def get_object(self):
        
        return self.request.user
@api_view(['POST'])
def login_view(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({"detail": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    # Authenticate user
    user_auth = authenticate(request, username=email, password=password)
    if not user_auth:
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    # Generate JWT tokens (optional if you're using JWT)
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)

    # Return response including role (no need to send role from frontend)
    return Response({
        "message": "Login successful",
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role
            # "name": f"{user.first_name} {user.last_name}".strip() or user.email,
        },
        "tokens": {
            "access": access_token,
            "refresh": str(refresh)
        }
    }, status=status.HTTP_200_OK)

@login_required
def google_login_callback(request):
    user = request.user

    social_account = SocialAccount.objects.filter(user=user)
    print("Social Account for User: ", social_account)
    
    social_account = social_account.first() 

    if not social_account:
        print("Social Account not exists for user:", user )
        return redirect('https://127.0.0.1:8000/login/callback?error=NoSocialAccount')  # Redirect to login if no social account found
    token = SocialToken.objects.filter(account__user=user, account__provider='google').first()
    if token:
        print("Google Token for User: ", token.token)
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        return redirect(f'https://127.0.0.1:8000/login/callback?token={access_token}')  
    else:
        print("No Google Token found:", user )
        return redirect('https://127.0.0.1:8000/login/callback?error=NoGoogleToken')  # Redirect to login if no token found
@csrf_exempt
def validation_Google_token(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            google_access_token = data.get('access_token')
            print(google_access_token)
            if not google_access_token:
                return JsonResponse({'error': 'Access token is missing'}, status=400) 
            return JsonResponse({'valid': True})
        except json.JSONDecodeError:
            return JsonResponse({'detail': 'Invalid JSON'}, status=400) 
    return JsonResponse({'detail': 'Method not allowed'}, status=405)