#!/usr/bin/env python3
"""
Routes file
"""

from flask import Flask, jsonify, request, abort, make_response, redirect
from flask import Response
from flask import url_for, Blueprint
from auth import Auth
from sqlalchemy import create_engine, text


api_routes = Blueprint('api_route', __name__, url_prefix='/api')
auth_routes = Blueprint('auth_route', __name__, url_prefix='/auth')
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
        new_user = AUTH.register_user(**rj)
    except TypeError as e:
        return jsonify({'errors': e.args[0]}), 422
    except ValueError:
        err_msg = {
            "status": "Bad request",
            "message": "Registration unsuccessful",
            "statusCode": 400
        }
        return jsonify(err_msg), 400


    jwtoken = AUTH.make_token(new_user.userId)
    ret_msg = {
        "status": "success",
        "message": "Registration successful",
        "data": {
            "accessToken": jwtoken,
            "user": new_user.to_dict()
        }
    }

    return jsonify(ret_msg), 201


#TODO Add JWT token to response header
@auth_routes.route('/login', methods=['POST'])
def login() :
    """Endpoint to log user in
    """
    rj = request.get_json()
    user = AUTH.valid_login(*rj.values())

    if (user):
        jwtoken = AUTH.make_token(user.userId)
        res_msg = {
            "status": "success",
            "message": "Login successful",
            "data": {
                "accessToken": jwtoken,
                "user": user.to_dict()
            }
        }

                # TODO
        resp = make_response(jsonify(res_msg))

        # cookie_name = 'session_id'
        # cookie_val = AUTH.create_session(rj['email'])
        # resp.set_cookie(cookie_name, cookie_val)

        return resp
    else:
        err_msg = {
            "status": "Bad request",
            "message": "Authentication failed",
            "statusCode": 401
        }
        return jsonify(err_msg), 401


#TODO JWT PROTECTED
@api_routes.route('/users/<id>')
@AUTH.token_required
def get_user(auth_user, id) -> Response:
    """
    User gets their own record or user record in organisations
    """
    retr_user = AUTH.authorize_for_user(auth_user, id)

    res_msg = {
        "status": "success",
        "message": "<message>",
        "data": retr_user and retr_user.to_dict()
    }
    return jsonify(res_msg)

#TODO JWT PROTECTED
@api_routes.route('/organisations')
@AUTH.token_required
def get_all_orgs(auth_user) -> Response:
    """
    gets all your organisations the user belongs to or created.
    If a user is logged in properly, they can get all their organisations.
    """
    all_orgs = AUTH.get_orgs(user_id=auth_user.userId)

    if not all_orgs:
        return jsonify({"message": "Invalid Request"}), 400

    res_msg = {
        "status": "success",
        "message": "<message>",
        "data": {
            "organisations": all_orgs
        }
    }

    return jsonify(res_msg)



#TODO JWT PROTECTED
@api_routes.route('/organisations/<orgId>')
@AUTH.token_required
def get_org(auth_user, orgId):
    """
    the logged in user gets a single organisation record [PROTECTED]
    """
    org = AUTH.get_orgs(user_id=auth_user.userId, org_id=orgId)

    if not org:
        return jsonify({"message": "Invalid Request"}), 400

    res_msg = {
        "status": "success",
        "message": "<message>",
        "data": org
    }

    return jsonify(res_msg), 200

#TODO JWT PROTECTED
@api_routes.route('/organisations/', methods=['POST'])
@AUTH.token_required
def create_org(auth_user) -> Response:
    """
    a user can create their new organisation [PROTECTED].
    Request body: request body must be validated
    """
    rj = request.get_json()

    try:
        org = AUTH.register_org(user_obj=auth_user, **rj)
    except TypeError as e:
        return jsonify({'errors': e}), 422
    except ValueError:
        err_msg = {
            "status": "Bad Request",
            "message": "Client error",
            "statusCode": 400
        }
        return jsonify(err_msg), 400

    res_msg = {
        "status": "success",
        "message": "Organisation created successfully",
        "data": org.to_dict()
    }
    return jsonify(res_msg), 201


@api_routes.route('/organisations/<orgId>/users', methods=['POST'])
def add_org_user(orgId) -> Response:
    """
    adds a user to a particular organisation
    """
    rj = request.get_json()

    org = AUTH.get_orgs(org_id=orgId)
    if org:
        user = AUTH.get_user(rj.get('userId'))
        ret_value = AUTH.add_user_to_org(org, user)

    if ret_value:
        res_msg = {
            "status": "success",
            "message": "User added to organisation successfully",
        }
        return jsonify(res_msg), 200
    else:
        abort(400)
