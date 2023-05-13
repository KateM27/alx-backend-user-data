#!/usr/bin/env python3
"""Hashing passwords"""

from bcrypt import hashpw, gensalt, checkpw
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from typing import Union
from user import User
import uuid


def _hash_password(password: str) -> bytes:
    """return a salted hash of the input password
    """
    return hashpw(password.encode(), gensalt())


def _generate_uuid() -> str:
    """return a str rep of a new uuid
    """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """
    def __init__(self):
        """Intialize class
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register users
        """
        try:
            users = self._db.find_user_by(email=email)
            if users:
                raise ValueError(f"User {email} already exists.")
        except NoResultFound:
            hashed_password = _hash_password(password).decode('utf-8')
            user = self._db.add_user(email, hashed_password)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """locate a user by email and check their password"""
        if not email or not password:
            return False
        try:
            users = self._db.find_user_by(email=email)
            hashed_password = users.hashed_password
            return checkpw(password.encode(),
                           hashed_password.encode('utf-8'))
        except (NoResultFound, InvalidRequestError):
            return False

    def create_session(self, email: str) -> Union[str, None]:
        """create a new session for users
        """
        user = self._db.find_user_by(email=email)
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """ Get a user from the session_id
        """
        if not session_id:
            return None

        user = self._db.find_user_by(session_id=session_id)
        if user:
            return
        else:
            return None

    def destroy_session(self, user_id: int) -> None:
        """ Destroy a user session
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except ValueError:
            pass

    def get_reset_password_token(self, email: str) -> str:
        """ Get reset password token
        """
        try:
            user = self._db.find_user_by(email=email)
            if user.reset_token:
                return user.reset_token
            token = _generate_uuid()
            self._db.update_user(user.id, reset_token=token)
            return token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """ Update user password
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password).decode('utf-8')
            self._db.update_user(user.id, hashed_password=hashed_password,
                                 reset_token=None)
        except NoResultFound:
            raise ValueError
