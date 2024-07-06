#!/usr/bin/env python3
"""
Auth Module
"""
import bcrypt
from db import DB
from uuid import uuid4
from typing import Union, TypeVar
from models.user import User
from flask import abort, request, jsonify
from sqlalchemy.exc import NoResultFound, InvalidRequestError
from sqlalchemy import text

from functools import wraps
import jwt
from datetime import datetime, timedelta, timezone

ATTRIBS_USER = ['userId', 'email', 'lastName', 'firstName', 'password', 'phone']
ATTRIBS_ORG = ['orgId', 'name', 'description']



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

    for key in field_dict.keys():
        if type(field_dict[key]) != str:
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
            user = self._db.find_user_by(email=kwargs.get('email'))
        except NoResultFound:
            h_pwd = _hash_password(kwargs.get('password'))
            kwargs['password'] = h_pwd
            user = self._db.add_user(**kwargs)

            org_name = "{}'s Organisation".format(kwargs.get('firstName'))
            org = self.register_org(org_name, None)

            user.user_organisations.append(org)
            self._db.commit()

            return user
        else:
            raise ValueError('User {} already exists'.format(kwargs.get("email")))


    def register_org(self, name=None, description=None, user_obj=None):
        """
        This method should take mandatory email and password string arguments
        and return a Organisation object.

        Args:
            org_name(`str`): The name of Organisation.
            desc(`str`): Description of org
        """

        fields = {'name': name, 'description': description}
        field_validation_errors = validate_fields(fields)
        if field_validation_errors:
            raise TypeError(field_validation_errors)

        if name is None:
            raise ValueError('Invalid parameters')

        new_org = self._db.add_org(name, description)
        if user_obj:
            user.user_organisations.append(org)
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
            if bcrypt.checkpw(b_pwd, user.hashed_password):
                return True
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

    def get_orgs(self, user_id=None, org_id=None):
        """
        """
        try:
            # Use token to find user/user id
            if user_id:
                user = self.get_user(user_id)
                if not user:
                    return {} if org_id else []

                orgs_list = list(map(lambda org: org.to_dict(),
                                     user.user_organisations))

                if org_id:
                    org = list(filter(lambda org: org.orgId==org_id,
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

    def user_from_token(jwtoken):
        if jwtoken is None:
            return None
        return self._db.find_user_by(email="bob@hbtn.io")



    def authorize_user(token):
        auth_user = self.user_from_token(token)

        if auth is None:
            abort(401)
        else:
            return auth_user

    def authorize_for_user(auth_user, user_id):
        retrieved_user_present = False
        retrieved_user = self.get_user(user_id)
        if not retrieved_user:
            return {}
        if retrieved_user.userId == auth_user.userId:
            return auth_user

        auth_orgs_list = auth_user.user_organisations
        for org in auth_orgs_list:
            if retrieved_user in org.organisation_users:
                retrieved_user_present = True
                break

            if retrieved_user_present:
                return retrieved_user
            else:
                return jsonify({'message' : 'Unauthorized'}), 401


    def get_authorized_user(token=None):
        auth_user = self.user_from_token(token)

        if auth_user is None:
            abort(401)
        else:
            return auth_user


    def add_user_to_org(org, user):
        if org and user:
            org.organisation_users.append(user)
            self._db.commit()
        return org

    def make_token(userid_payload):
        token = jwt.encode({
            'userId': userid_payload,
            'expiration': (datetime.now(timezone.utc) +
                           timedelta(minutes=10)).isoformat()
        }, app.config['FLASK_SECRET_KEY'])

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
                # decoding the payload to fetch the stored details
                d_token = jwt.decode(token, app.config['FLASK_SECRET_KEY'],
                                     algorithms=["HS256"])

                if datetime.fromisoformat(d_token['expiration']) >\
                        datetime.now(timezone.utc):
                    current_user = self.get_user(d_token['userId'])
                else:
                    current_user = None


                if not current_user:
                    raise ValueError
            except:
                return jsonify({
                    'message' : 'Token is invalid !!'
                }), 401
                # returns the current logged in users context to the routes
            return f(current_user, *args, **kwargs)
        return decorated
