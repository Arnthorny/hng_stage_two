#!/usr/bin/python3
"""Defines an Organisation class"""

from models.base_model import BaseModel, Base
from sqlalchemy import Column, String, Table, ForeignKey
from sqlalchemy.orm import relationship

user_orgs = Table(
        "user_organisation",
        Base.metadata,
        Column(
            "user_id",
            String(60),
            ForeignKey("users.userId"),
            primary_key=True,
            nullable=False),
        Column(
            "org_id",
            String(60),
            ForeignKey("organisations.orgId"),
            primary_key=True,
            nullable=False))




class Organisation(BaseModel, Base):
    """Represents an Organisation"""

    __tablename__ = "organisations"
    orgId = Column('orgId', String(60), primary_key=True)

    name = Column(String(250), nullable=False)

    description = Column(String(250), nullable=True)

    organisation_users = relationship(
                "User",
                secondary=user_orgs,
                back_populates="user_organisations"
                )

    user_ids = []


    def to_dict(self):
        """
        Convert organisation object to suitable dictionary
        {
            "orgId": "string",
            "name": "string",
            "description": "string",
        }
        """
        return super().to_dict()

    @property
    def users(self):
        """"Gets the attribute"""
        return self.user_ids

    @users.setter
    def users(self, obj):
        """Sets the attribute"""
        if obj.userId not in self.user_ids:
            self.user_ids.append(obj.id)
