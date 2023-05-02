#!/usr/bin/env python3
"""Module of authentication"""
from typing import List, TypeVar
from flask import request


class Auth:
    """Class to manage the API authentication"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Public method to validate authentication"""
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        if len(excluded_paths) == 0:
            return True

        path = path + '/' if path[-1] != '/' else path

        if path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """method handles authorization header"""
        if request is None:
            return None
        if 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """method validates current user"""
        return None
