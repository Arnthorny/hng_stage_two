#!/usr/bin/env python3
"""
Routes file
"""

from flask import Flask, jsonify, request, abort, make_response, redirect
from flask import Response
from flask import url_for, Blueprint
from auth import Auth


api_routes = Blueprint('/api/', __name__)
auth_routes = Blueprint('/auth/', __name__)
AUTH = Auth()


@auth_routes.route('/register', methods=['POST'])
def register_user() -> Response:
    """Endpoint to register user
    Return:
      - Confirmation JSON message
      - 400 if error
    """
    rj = request.get_json()
    try:
        new_user = Auth.register_user(**rj)
    except ValueError:
        err_msg =
        {
            "status": "Bad request",
            "message": "Registration unsuccessful",
            "statusCode": 400
        }
        return jsonify(err_msg), 400

    ret_msg =
    {
        "status": "success",
        "message": "Registration successful",
        "data": {
            "accessToken": "eyJh...",
            "user": new_user.to_dict()
        }
    }

    return jsonify(ret_msg), 201


#TODO Add JWT token to response header
@auth_routes.route('/login', methods=['POST'])
def login() -> Response:
    """Endpoint to log user in
    Form body:
      - email
      - password
    Return:
      - Confirmation JSON message
      - 401 if info is incorrect
    """
    rj = request.get_json()
    user = Auth.valid_login(*rj.values())

    if (user):
        res_msg = {
            "status": "success",
            "message": "Login successful",
            "data": {
                "accessToken": "eyJh...",
                "user": user.to_dict()
            }
        }

        # TODO
        resp = make_response(jsonify(res_msg))

        cookie_name = 'session_id'
        cookie_val = AUTH.create_session(rj['email'])
        resp.set_cookie(cookie_name, cookie_val)

        return resp
    else:
        err_msg = {
            "status": "Bad request",
            "message": "Authentication failed",
            "statusCode": 401
        }
        return jsonify(err_msg), 401


@api_routes.route('/users/<id>')
#TODO JWT PROTECTED
def get_user(id) -> Response:
    """
    User gets their own record or user record in organisations
    """
    jwtoken = None
    try:
        user = Auth.get_user(id, jwtoken)
    except ValueError:
        abort(401)

    res_msg = {
        "status": "success",
        "message": "<message>",
        "data": user.to_dict()
    }
    return jsonify(res_msg)

@api_routes.route('/organisations')
#TODO JWT PROTECTED
def get_all_orgs() -> Response:
    """
    gets all your organisations the user belongs to or created.
    If a user is logged in properly, they can get all their organisations.
    """
    try:
        org = Auth.get_orgs()
        all_orgs = None
    except ValueError:
        abort(401)

    res_msg =
    {
        "status": "success",
        "message": "<message>",
        "data": {
            "organisations": all_orgs
        }
    }

    return jsonify(res_msg)



@api_routes.route('/organisations/<orgId>')
#TODO JWT PROTECTED
def get_org(orgId) -> Response:
    """
    the logged in user gets a single organisation record [PROTECTED]
    """
    try:
        org = Auth.get_org(orgId)
    except ValueError:
        abort(401)

    res_msg =
    {
        "status": "success",
        "message": "<message>",
        "data": org.to_dict()
    }

    return jsonify(res_msg), 200

@api_routes.route('/organisations/', methods=['POST'])
#TODO JWT PROTECTED
def create_org() -> Response:
    """
    a user can create their new organisation [PROTECTED].
    Request body: request body must be validated
    """
    rj = request.get_json()
    try:
        org = Auth.register_org(**rj)
    except ValueError:
        err_msg = {
            "status": "Bad Request",
            "message": "Client error",
            "statusCode": 400
        }
        return jsonify(err_msg), 400

    res_msg =
    {
        "status": "success",
        "message": "<message>",
        "data": org.to_dict()
    }
    return jsonify(res_msg), 200


@api_routes.route('/organisations/<orgId>/users', methods=['POST'])
def add_org_user(orgId) -> Response:
    """
    adds a user to a particular organisation
    """
    rj = request.get_json()
    try:
        org = Auth.add_org_user(**rj)
    except ValueError:
        abort(400)

    res_msg =
    {
        "status": "success",
        "message": "User added to organisation successfully",
    }

    return jsonify(res_msg), 200
