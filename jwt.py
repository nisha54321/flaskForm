import psycopg2
from flask import Flask, request, jsonify, make_response, render_template
from flask_sqlalchemy import SQLAlchemy
import uuid 
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps


connection = psycopg2.connect(user="postgres", password="postgres", host="localhost", database="flask_jwt_auth")
cursor = connection.cursor()
cursor.execute("SELECT public_id FROM jwt_token")
key = cursor.fetchall()
key = str(key[0])
key = key.replace("('", "")
key = key.replace("',)", "")
print(key)

app = Flask(__name__)

app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['JWT_ALGORITHM'] = 'HS256'


#generate token
token = jwt.encode({
    'public_id': key,
    'exp' : datetime.utcnow() + timedelta(minutes = 30)
}, app.config['SECRET_KEY'])


print("token::",token)

#decode token
data = jwt.decode(token, app.config['SECRET_KEY'], app.config['JWT_ALGORITHM'])

print("decode ::   ",data)

 
cursor.close()
connection.close()       
