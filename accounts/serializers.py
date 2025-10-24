from rest_framework import serializers
from .models import CustomUser
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
 

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['email', 'password', 'full_name', 'company_name', 'role']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        email = data.get('email')
        role = data.get('role')

        # ✅ Check if email already exists with the same role
        if CustomUser.objects.filter(email=email, role=role).exists():
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
        user.set_password(password)
        user.save()
        return user
 
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['role'] = user.role  # optional claim
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        data['user'] = {
            # 'username': self.user.username,  # ❌ Remove this
            'email': self.user.email,
            'role': self.user.role,
        }
        return data
