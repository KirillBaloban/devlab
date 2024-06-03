import re


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
