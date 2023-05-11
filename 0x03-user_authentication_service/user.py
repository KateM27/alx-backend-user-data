#!/usr/bin/env python3
"""The User model"""

from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    """The class User"""
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), null=False)
    hashed_password = Column(String(250), null=False)
    session_id = Column(String(250), null=True)
    reset_token = Column(String(250), null=True)
