#source env/bin/activate
from flask import Blueprint, render_template, flash
from flask import redirect, url_for, request, flash, Flask, jsonify, make_response
from flask_login import login_required, current_user
import jwt
from datetime import datetime, timedelta
import uuid 
from functools import wraps

from models import User
from __init__ import create_app, db

main = Blueprint('main', __name__)

@main.route('/') 
def index():
    return render_template('index.html')

@main.route('/profile') 
def profile():
    return render_template('profile.html', name=current_user.name)

##
def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None
		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']
		if not token:
			return jsonify({'message' : 'Token is missing !!'}), 401

		try:
			data = jwt.decode(token, app.config['SECRET_KEY'])
			current_user = User.query.filter_by(public_id = data['public_id']).first()
		except:
			return jsonify({
				'message' : 'Token is invalid !!'
			}), 401
		return f(current_user, *args, **kwargs)
	return decorated

@main.route('/user', methods =['GET'])
@token_required
def user(current_user):
	users = User.query.all()
	output = []
	for user in users:
	
		output.append({
			'public_id': user.public_id,
			'name' : user.name,
			'email' : user.email
		})
	print("output", output)
	#return jsonify({'users': output})
	return render_template('user.html', output=output)


app = create_app() 
if __name__ == '__main__':
    db.create_all(app=create_app()) 
    app.run(debug=True) 
