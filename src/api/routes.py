"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

#------------------signup------------------

@api.route("/signup", methods=["POST"])
def signup():
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')

    if not username or not email or not password:
        return jsonify({"error": "Missing required parameters"}), 400
    
    if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exist"}), 409
    
    user = User(email=email, username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    token = user.generate_token()
    return jsonify({"token": token}), 201


#------------------login------------------

@api.route("/login", methods=["POST"])
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    if not email or not password:
        return jsonify({"error": "Missing required parameters"}), 400
    
    user = User.query.filter_by(email=email).first()

    if user is None or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    token = user.generate_token()
    return jsonify({"token": token}), 200


#----------------get private data----------

@api.route("/private", methods=["GET"])
@jwt_required()
def get_private_data():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    return jsonify({"Private Data": user.serialize()}), 200

#----------------update user--------------

@api.route("/user", methods=["PUT"])
@jwt_required()
def update_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "User not Found"}), 404
    
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')

    if username:
        user.username = username
    if email:
        user.email = email
    if password:
        user.set_password(password)

    db.session.commit()

    return jsonify({"msj": "User Updated successfully", "user": user.serialize()}), 200


#-------------delete user---------------

@api.route('/user', methods=['DELETE'])
@jwt_required
def delete_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "user not found"}), 404
    
    db.session.delete(user)
    db.session.commit()

    return jsonify({"msj": "User deleted successfully"}), 200