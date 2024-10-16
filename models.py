from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from db import db  # Import db from the new db.py file

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    points = db.Column(db.Integer, default=0)
    is_deleted = db.Column(db.Boolean, default=False)  # Soft delete flag
    points_history = db.relationship('PointsHistory', backref='employee', lazy=True, cascade="all, delete-orphan")

    # Single relationship to User (avoid multiple backrefs)
    user = db.relationship('User', back_populates='employee', uselist=False)

class PointsHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    points = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment = db.Column(db.String(255), nullable=False)

    # Relationship to User (this backref works for historical tracking of who added points)
    user = db.relationship('User', backref='points_history')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    role = db.Column(db.String(50), nullable=False)

    # Foreign key linking to Employee table
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=True)

    # Relationship to Employee (make this back_populates to link it properly)
    employee = db.relationship('Employee', back_populates='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
