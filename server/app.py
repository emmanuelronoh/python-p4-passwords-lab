#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from config import app, db, api
from models import User

class ClearSession(Resource):
    def delete(self):
        session.clear()  # Clear all session data
        return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()
        if not json or 'username' not in json or 'password' not in json:
            return {'error': 'Username and password required'}, 400
        
        # Check for existing username
        existing_user = User.query.filter_by(username=json['username']).first()
        if existing_user:
            return {'error': 'Username already exists'}, 400
        
        user = User(username=json['username'])
        user.password_hash = json['password']  # Password is hashed in the model
        db.session.add(user)
        db.session.commit()
        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user:
                return user.to_dict(), 200
        
        return {}, 204  # Changed from 401 to 204

class Login(Resource):
    def post(self):
        json = request.get_json()
        if not json or 'username' not in json or 'password' not in json:
            return {'error': 'Username and password required'}, 400
            
        user = User.query.filter_by(username=json['username']).first()
        if user and user.authenticate(json['password']):
            session['user_id'] = user.id
            return {'username': user.username}, 200
        return {'error': 'Invalid credentials'}, 401

class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)  # Remove user_id from session
        return {}, 204

# Register resources with API
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
