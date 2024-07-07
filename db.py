#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine, column
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import NoResultFound, InvalidRequestError, IntegrityError

from uuid import uuid4
from models.user import Base, User
from models.organisation import Organisation

from typing import TypeVar, Dict, Any, Union
from os import getenv


URL_PARAMS = (getenv('HNG_2_USER'), getenv('HNG_2_PASSWORD'),
              getenv('HNG_2_HOST'), getenv('HNG_2_PORT'), getenv('HNG_2_DB'))


def _generate_uuid() -> str:
    """
    Return a string representation of a new UUID
    """
    return str(uuid4())


class DB:
    """DB class
    """
    ATTRIBS_USER = ['userId', 'email', 'lastName', 'firstName', 'password', 'phone']
    ATTRIBS_ORG = ['orgId', 'name', 'description']

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        # self._engine = create_engine(
        #     "postgresql+psycopg://{}:{}@{}:{}/{}".format(*URL_PARAMS_TEST)
        # )
        self._engine =
        create_engine("postgresql+psycopg://{}:{}@{}:{}/{}".format(*URL_PARAMS))

        # Base.metadata.drop_all(self._engine)
        # Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine, expire_on_commit=False)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email, password, firstName, lastName, phone=None) -> User:
        """
        The method, which has two required string arguments: email and
        hashed_password, and returns a User object. The method should save the
        user to the database

        Arguments:
            email(`str`): The user's email.
            hashed_password(`str`): The user's password
        """
        u_id = _generate_uuid()

        new_user = User(userId=u_id, email=email, password=password,
                        firstName=firstName, lastName=lastName, phone=phone)
        self._session.add(new_user)

        return new_user

    def commit(self):
        self._session.commit()

    def rollback(self):
        self._session.rollback()

    def add_org(self, org_name, desc) -> User:
        """
        Arguments:
            org_name(`str`): The name of Organisation.
            desc(`str`): Description of org
        """
        org_id = _generate_uuid()

        new_org = Organisation(orgId=org_id, name=org_name, description=desc)
        self._session.add(new_org)

        return new_org

    def find_user_by(self, **kwargs) -> User:
        """
        This method takes in keyword arguments and returns the first
        row found in the users table.
        """

        user = self._session.query(User).filter_by(**kwargs).first()
        if user is None:
            raise NoResultFound
        return user

    def find_org_by(self, **kwargs) -> Organisation:
        """
        This method takes in keyword arguments and returns the first
        row found in the organisations table.
        """
        org = self._session.query(Organisation).filter_by(**kwargs).first()
        if org is None:
            raise NoResultFound
        return org
