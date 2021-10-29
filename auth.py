from flask import Blueprint, render_template, redirect, url_for, request, flash, Flask, jsonify, make_response

from werkzeug.security import generate_password_hash, check_password_hash
from models import User
from flask_login import login_user, logout_user, login_required, current_user
import jwt
from datetime import datetime, timedelta
import uuid 
from functools import wraps

from __init__ import db


auth = Blueprint('auth', __name__) 
app = Flask(__name__) 
app.config['SECRET_KEY'] = 'secretkeygoeshere' 
app.config['JWT_ALGORITHM'] = 'HS256'

#jwt

@auth.route('/login', methods=['GET', 'POST']) 
def login(): 
    if request.method=='GET': 
        return render_template('login.html')
    else: 
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Please sign up before!')
            return redirect(url_for('auth.signup'))

        elif not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login')) 
            
        # #jwt
        # elif check_password_hash(user.password, password):
        #     #generate token
        #     token = jwt.encode({
        #         'public_id': user.public_id,
        #         'exp' : datetime.utcnow() + timedelta(minutes = 30)
        #     }, app.config['SECRET_KEY'])

        #     print("token::",token)

        #     #cookies
        #     resp = make_response(f'Successfully Logged in as {user.name}', 200)
        #     resp.set_cookie('x-access-token', token, expires=datetime.utcnow() + timedelta(minutes = 30))
        #     print("cookies  ::  ",resp)


        #     #decode token
        #     data = jwt.decode(token, app.config['SECRET_KEY'], app.config['JWT_ALGORITHM'])

        #     print("decode ::   ",data)

        #     return make_response(jsonify({'token' : token}), 201)
        #automatically after 5 minuts logout

        session.permanent = False

        login_user(user, remember=remember)
        return redirect(url_for('main.profile'))
        
        
@auth.route('/signup', methods=['GET', 'POST'])
def signup(): 
    if request.method=='GET': 
        return render_template('signup.html')
    else: 
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        public_id = str(uuid.uuid4()),
        # public_id = "helooo1233"
        user = User.query.filter_by(email=email).first() 
        if user: 
            flash('Email address already exists')
            return redirect(url_for('auth.signup'))

        new_user = User(public_id = public_id, email=email, name=name, password=generate_password_hash(password, method='sha256')) #

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('auth.login'))



@auth.route('/logout') 
@login_required
def logout(): 
    logout_user()
    return redirect(url_for('main.index'))
