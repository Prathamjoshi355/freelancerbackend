"""
Custom authentication backend for MongoEngine users with JWT
"""
from rest_framework_simplejwt.authentication import JWTAuthentication  
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed
from accounts.models import CustomUser


class MongoEngineJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication that works with MongoEngine.
    Properly handles both authenticated and unauthenticated requests.
    """
    
    def authenticate(self, request):
        """
        Override to handle MongoEngine users and allow unauthenticated requests.
        Returns None if no auth header, allowing AllowAny views to work.
        """
        # Get the auth header
        auth_header = self.get_header(request)
        
        # If no auth header, return None (not authenticated, but allowed)
        if auth_header is None:
            return None
        
        # If auth header exists, validate it using parent class
        try:
            # Use parent's get_validated_token but catch errors differently
            validated_token = self.get_validated_token(auth_header)
            user = self.get_user(validated_token)
            return (user, validated_token)
        except InvalidToken as exc:
            raise AuthenticationFailed(str(exc))
        except AuthenticationFailed:
            raise
    
    def get_user(self, validated_token):
        """
        Override to get user from MongoDB instead of Django ORM.
        Uses MongoEngine's ObjectId string representation.
        """
        try:
            user_id = validated_token.get('user_id')
            if not user_id:
                raise InvalidToken('Token is missing user_id claim')
        except (KeyError, AttributeError, TypeError):
            raise InvalidToken('Token is missing user_id claim')
        
        try:
            # MongoDB ObjectId is stored as string in JWT
            user = CustomUser.objects(id=user_id).first()
            if not user:
                raise AuthenticationFailed(f'User not found')
            return user
        except AuthenticationFailed:
            raise
        except Exception as e:
            raise AuthenticationFailed(f'Error fetching user')



