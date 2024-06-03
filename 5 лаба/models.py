from datetime import datetime, UTC

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    first_name = db.Column(db.String(50))
    middle_name = db.Column(db.String(50))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    role = db.relationship('Role')
    creation_date = db.Column(db.DateTime, default=datetime.now(UTC))

    def get_full_name(self):
        return f'{self.last_name} {self.first_name} {self.middle_name}'


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))


class VisitLogs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(), nullable=False)
    page = db.Column(db.String(), nullable=False)
    creation_date = db.Column(db.DateTime, default=datetime.now(UTC))
