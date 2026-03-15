from rest_framework import serializers
from .models import CustomUser
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
 

class UserSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)
    full_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    company_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    role = serializers.ChoiceField(choices=['freelancer', 'client'], required=True)

    def validate(self, data):
        email = data.get('email')
        role = data.get('role')

        # ✅ Check if email already exists with the same role (MongoEngine syntax)
        if CustomUser.objects(email=email, role=role).count() > 0:
            raise serializers.ValidationError({
                "email": f"This email is already registered as a {role.capitalize()}."
            })

        # Role-based validation (your existing logic)
        if role == 'freelancer':
            if not data.get('full_name'):
                raise serializers.ValidationError({"full_name": "Full name is required for freelancers."})
            data.pop('company_name', None)

        elif role == 'client':
            if not data.get('company_name'):
                raise serializers.ValidationError({"company_name": "Company name is required for clients."})
            data.pop('full_name', None)

        else:
            raise serializers.ValidationError({"role": "Invalid role. Must be 'freelancer' or 'client'."})

        return data

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = CustomUser(**validated_data)
        user.set_password(password)  # This also calls save()
        return user
 
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'email'  # Use email instead of username
    
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['role'] = user.role  # optional claim
        return token

    def validate(self, attrs):
        # Convert email to username for parent class
        authenticate_kwargs = {
            'username': attrs.get('email'),
            'password': attrs.get('password'),
        }
        
        from django.contrib.auth import authenticate
        try:
            user = CustomUser.objects.get(email=attrs.get('email'))
            if not user.check_password(attrs.get('password')):
                raise serializers.ValidationError({'detail': 'Invalid credentials'})
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError({'detail': 'Invalid credentials'})
        
        refresh = self.get_token(user)
        data = {'refresh': str(refresh), 'access': str(refresh.access_token)}
        data['user'] = {
            'email': user.email,
            'role': user.role,
        }
        return data
