#!/usr/bin/env python3
"""
Auth Module
"""
import bcrypt
from db import DB
from uuid import uuid4
from models.user import User
from flask import abort, request, jsonify

from sqlalchemy.exc import NoResultFound, InvalidRequestError, IntegrityError

from os import getenv
from functools import wraps
import jwt
from datetime import datetime, timedelta, timezone

ATTRIBS_USER = ['userId', 'email', 'lastName', 'firstName', 'password', 'phone']
ATTRIBS_ORG = ['orgId', 'name', 'description']

SECRET_KEY = getenv('FLASK_SECRET_KEY')


def _hash_password(password: str) -> bytes:
    """
    This method takes in a password string arguments and returns bytes.
    The returned bytes is a salted hash of the input password, hashed with
    bcrypt.hashpw.
    """
    p_bytes = bytes(password, 'utf-8')
    p_hash = bcrypt.hashpw(p_bytes, bcrypt.gensalt())
    return p_hash

def validate_fields(field_dict):
    err_list = []

    for key in ATTRIBS_USER[1:]:
        if key != 'phone' and type(field_dict.get(key)) != str:
            err_obj = {
                "field": key,
                "message": "string"
            }
            err_list.append(err_obj)

    return err_list

class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, **kwargs):
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
        field_validation_errors = validate_fields(kwargs)
        if field_validation_errors:
            raise TypeError(field_validation_errors)

        for field in ATTRIBS_USER[1:]:
            if field != 'phone' and kwargs.get(field) is None:
                raise ValueError('Invalid parameters')

        try:
            h_pwd = _hash_password(kwargs.get('password'))
            kwargs['password'] = h_pwd.decode("utf-8")
            user = self._db.add_user(**kwargs)

            org_name = "{}'s Organisation".format(kwargs.get('firstName'))
            org = self.register_org(org_name, None)

            user.user_organisations.append(org)
            self._db.commit()

            return user
        except IntegrityError:
            self._db.rollback()
            raise ValueError('User {} already exists'.format(kwargs.get("email")))


    def register_org(self, name=None, description=None, user_obj=None):
        """
        This method should take mandatory email and password string arguments
        and return a Organisation object.

        Args:
            org_name(`str`): The name of Organisation.
            desc(`str`): Description of org
        """
        if name is None:
            raise ValueError('Invalid parameters')

        new_org = self._db.add_org(name, description)
        if user_obj:
            user_obj.user_organisations.append(new_org)
            self._db.commit()
        return new_org


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
            if bcrypt.checkpw(b_pwd, bytes(user.password, 'utf-8')):
                return user
        except NoResultFound:
            pass
        return False

    def get_user(self, user_id=None):
        """
        This method takes a single session_id string argument and returns the
        corresponding User or None.
        """
        if user_id is None:
            return None
        try:
            user = self._db.find_user_by(userId=user_id)
            return user
        except NoResultFound:
            pass
        return {}

    def get_orgs(self, user=None, org_id=None):
        """
        """
        orgs_list = []
        try:
            if user:
                orgs_list = list(map(lambda org: org.to_dict(),
                                     user.user_organisations))

                if org_id:
                    org = list(filter(lambda org: org['orgId']==org_id,
                                      orgs_list)) or {}
                    return org
                else:
                    return orgs_list

            else:
                org = self._db.find_org_by(orgId=org_id)
                return org
        except NoResultFound:
            pass
        return {}


    def authorize_for_user(self, auth_user, user_id):
        retrieved_user_present = False
        org_usr = []

        retrieved_user = self.get_user(user_id)
        if user_id == auth_user.userId:
            return auth_user

        auth_orgs_list = auth_user.user_organisations
        for orgs in auth_orgs_list:
            org_usr = list(filter(lambda x: x.userId == retrieved_user.userId,
                                  orgs.organisation_users))
            if org_usr:
                retrieved_user_present = True
                break

        if retrieved_user_present:
            return retrieved_user
        else:
            raise ValueError('Unauthorized')


    def add_user_to_org(self, org, user):
        if org and user:
            if user not in org.organisation_users:
                org.organisation_users.append(user)
                self._db.commit()
            return org
        return None

    def make_token(self, userid_payload):
        payload = {
            'userId': userid_payload,
            'exp': int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp())
        }

        token = jwt.encode(payload, SECRET_KEY)
        return token

    def token_required(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            # jwt is passed in the request header
            if bearer:= request.headers.get('Authorization'):
                token = bearer.split()[1]

            # return 401 if token is not passed
            if not token:
                return jsonify({'message' : 'Token is absent!'}), 401

            try:
                d_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                current_user = self.get_user(d_token['userId'])
            except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
                current_user = None

            if not current_user:
                return jsonify({
                    'message' : 'Token is invalid'
                }), 401
                # returns the current logged in users context to the routes
            return f(current_user, *args, **kwargs)
        return decorated
