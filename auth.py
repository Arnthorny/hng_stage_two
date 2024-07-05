#!/usr/bin/env python3
"""
Auth Module
"""
import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import Union, TypeVar
from user import User


def _hash_password(password: str) -> bytes:
    """
    This method takes in a password string arguments and returns bytes.
    The returned bytes is a salted hash of the input password, hashed with
    bcrypt.hashpw.
    """
    p_bytes = bytes(password, 'utf-8')
    p_hash = bcrypt.hashpw(p_bytes, bcrypt.gensalt())
    return p_hash


def _generate_uuid() -> str:
    """
    Return a string representation of a new UUID
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str, firstName: str,
                      lastName, phone: str) -> User:
        """
        This method should take mandatory email and password string arguments
        and return a User object.

        Args:
            email(`str`): The user's email.
            password(`str`): The user's password.

        Description:
            If a user already exist with the passed email, raise a ValueError
            with the message User <user's email> already exists.
            If not, hash the password with _hash_password, save the user to the
            database using self._db and return the User object
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            u_id = _generate_uuid()

            h_pwd = _hash_password(password)
            user = self._db.add_user(u_id, email, h_pwd, firstName, lastName,
                                     phone)
            org_id = _generate_uuid()
            org_name = f"{firsName}'s Organisation"
            org = self._db.add_org(org_id, org_name, None)

            return user
        else:
            raise ValueError('User {} already exists'.format(email))


    def register_org(self, name: str, description=None: str) -> User:
        """
        This method should take mandatory email and password string arguments
        and return a Organisation object.

        Args:
            email(`str`): The user's email.
            password(`str`): The user's password.

        Description:
            If a user already exist with the passed email, raise a ValueError
            with the message User <user's email> already exists.
            If not, hash the password with _hash_password, save the user to the
            database using self._db and return the User object
        """

        org_id = _generate_uuid()
        org = self._db.add_org(org_id, org_name, description)

        return org
        else:
            raise ValueError('Invalid request')



    def valid_login(self, email: str, password: str) -> bool:
        """
        This method should validate a user's email and password.

        Args:
            email(`str`): The user's email.
            password(`str`): The user's password.

        Returns:
            bool: True if valid else false
        """
        if type(email) != str or type(password) != str:
            return False
        try:
            user = self._db.find_user_by(email=email)
            b_pwd = bytes(password, 'utf-8')
            if bcrypt.checkpw(b_pwd, user.hashed_password):
                return True
        except NoResultFound:
            pass
        return False

    # Generate JWT token
    def create_jwt(self, email: str):
        """
        This method takes an email string argument and returns the session ID
        as a string

        Args:
            email(`str`): The user's email.

        Returns:
            (`str`): Session ID
        """
        try:
            user = self._db.find_user_by(email=email)
            sess_id = _generate_uuid()
            self._db.update_user(user.id, session_id=sess_id)

            return sess_id
        except NoResultFound:
            pass
        return None

    def get_user(self, user_id, token: str):
        """
        This method takes a single session_id string argument and returns the
        corresponding User or None.
        """
        try:
            # Verify token first
            user = self.find_user_by(id=user_id)
            return user
        except NoResultFound:
            pass
        return None

    def get_orgs(self, org_id=None):
        """
        """
        try:
            # Use token to find user/user id
            user_id = None
            # user = self.find_user_by(id=user_id)
            orgs = self.get_user_orgs(user_id, org_id)
            return user
        except NoResultFound:
            pass
        return None
