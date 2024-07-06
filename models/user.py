#!/usr/bin/env python3
"""
Module that contains definition of class User
"""

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String
from models.base_model import Base, BaseModel
from models.organisation import user_orgs
from sqlalchemy.orm import relationship


class User(BaseModel, Base):
    """
    This class inherits from Base and links to the Postgres table `users`

    Attributes:
    userId(str):    The primary key.
    email(str):     A Unique non-nullable string
    password(str):  A non-nullable string
    firstName(str): A non-nullable string
    lastName(str):  A non-nullable string
    phone(str):     A non-nullable string
    """
    __tablename__ = 'users'

    userId = Column('userId', String(60), primary_key=True)

    email = Column('email', String(250), nullable=False, unique=True)

    password = Column('password', String(250), nullable=False)

    firstName = Column('firstName', String(250), nullable=False)

    lastName = Column('lastName', String(250), nullable=False)

    phone = Column('phone', String(250), nullable=True)

    user_organisations = relationship(
        "Organisation",
        secondary=user_orgs,
        back_populates="organisation_users"
    )

    organisation_ids = []



    def to_dict(self):
        """
        Convert user object to suitable dictionary

        {
	      "userId": "string",
	      "firstName": "string",
          "lastName": "string",
          "email": "string",
          "phone": "string",
          }
        """
        return super().to_dict()

    @property
    def orgs(self):
        """"Gets the attribute"""
        return self.organisation_ids

    @orgs.setter
    def orgs(self, obj):
        """Sets the attribute"""
        if obj.orgId not in self.organisation_ids:
            self.organisation_ids.append(obj.id)
