from flask_login import UserMixin
from __init__ import db

class User(UserMixin, db.Model):
    __tablename__ = 'flask_form'

    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    public_id = db.Column(db.String(50), unique = True)

    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
