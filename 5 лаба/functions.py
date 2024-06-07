import re
from functools import wraps

from flask import flash, redirect, url_for
from flask_login import current_user

from constants import ACCESS_DENIED


def is_valid_password(password):
    if not password:
        return False
    if len(password) < 8 or len(password) > 128:
        return False
    if not re.search(r'[A-ZА-Я]', password) or not re.search(r'[a-zа-я]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.match(r'^[a-zA-Zа-яА-Я0-9]+$', password):
        return False
    return True


def check_rights(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role.name != 'admin':
            flash(ACCESS_DENIED, 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function
