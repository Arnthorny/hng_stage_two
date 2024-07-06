#!/usr/bin/python3
"""Defines a BaseModel class"""
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class BaseModel:
    """
    BaseModel
    """

    def to_dict(self):
        """Returns a dictionary of the instance"""
        unneded_attributes = ['password', '_sa_instance_state',
                              'user_organisations', 'organisation_users']

        attributes = self.__dict__.copy()

        for key in unneded_attributes:
            attributes.pop(key, None)


        return attributes
