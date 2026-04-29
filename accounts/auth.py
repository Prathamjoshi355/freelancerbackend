from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed, InvalidToken
from rest_framework_simplejwt.settings import api_settings

from accounts.models import CustomUser


class MongoEngineJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        return self.get_user(validated_token), validated_token

    def get_user(self, validated_token):
        user_id = validated_token.get(api_settings.USER_ID_CLAIM)
        if not user_id:
            raise InvalidToken("Token missing user id")

        user = CustomUser.objects(id=user_id).first()
        if user is None:
            raise AuthenticationFailed("User not found")
        if not user.is_active:
            raise AuthenticationFailed("User account is disabled")
        return user
