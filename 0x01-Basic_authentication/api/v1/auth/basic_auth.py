#!/usr/bin/env python3
"""Class BasicAuth that inherits from Auth"""
from base64 import b64decode
from typing import TypeVar
from api.v1.auth.auth import Auth
from models.user import User


class BasicAuth(Auth):
    """Class implements basic authentication"""
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Returns the Base64 part of the authorization header"""
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None

        Base64_encoded = authorization_header.split(' ', 1)[1]
        return Base64_encoded

    def decode_base64_authorization_header(self,
                                           base64_authorization_header:
                                           str) -> str:
        """Returns decoded value of authorization header"""
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            encoded_str = base64_authorization_header.encode('utf-8')
            decoded_str = b64decode(encoded_str)
            decoded_val = decoded_str.decode('utf-8')
        except BaseException:
            return None

        return decoded_val

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header:
                                 str) -> (str):
        """Returns the user email and password from decoded value"""
        if decoded_base64_authorization_header is None:
            return None, None

        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ':' not in decoded_base64_authorization_header:
            return None, None

        Usr_details = decoded_base64_authorization_header.split(':', 1)

        return Usr_details[0], Usr_details[1]

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """Returns the User instance based on his
        email and password"""
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        try:
            found_users = User.search({'email': user_email})
        except Exception:
            return None

        for user in found_users:
            if user.is_valid_password(user_pwd):
                return user

        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Overloads Auth and returns the User instance for a request"""
        auth_header = self.authorization_header(request)

        if not auth_header:
            return None

        encoded = self.extract_base64_authorization_header(auth_header)

        if not encoded:
            return None

        decoded = self.decode_base64_authorization_header(encoded)

        if not decoded:
            return None

        email, pwd = self.extract_user_credentials(decoded)

        if not email or not pwd:
            return None

        user = self.user_object_from_credentials(email, pwd)

        return user
