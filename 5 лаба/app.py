from functools import wraps

from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user, LoginManager
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User, Role
from functions import is_valid_password
from constants import ACCESS_DENIED
from visit_logs import visit_logs_bp, add_visit_log

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.register_blueprint(visit_logs_bp, url_prefix='/visits')

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)


def generate_defaults(db: SQLAlchemy):
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        admin_role = Role(**{
            'name': 'admin',
            'description': 'admin role'
        })
        db.session.add(admin_role)
        db.session.commit()

    default_user_role = Role.query.filter_by(name='default_user').first()
    if not default_user_role:
        default_user_role = Role(**{
            'name': 'default_user',
            'description': 'default user role'
        })
        db.session.add(default_user_role)
        db.session.commit()

    admin = User.query.filter_by(login='admin').first()
    if not admin:
        default_password = generate_password_hash('admin')
        admin = User(**{
            'login': 'admin',
            'password': default_password,
            'last_name': 'admin',
            'role_id': admin_role.id
        })
        db.session.add(admin)
        db.session.commit()


def check_rights(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role.name != 'admin':
            flash(ACCESS_DENIED, 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# Routes
@app.route('/')
@add_visit_log
def index():
    users = User.query.all()
    return render_template('index.html', users=users)


@app.route('/view/<int:user_id>')
@add_visit_log
def view(user_id):

    if user_id != current_user.id and current_user.role.name != 'admin':
        flash(ACCESS_DENIED, 'error')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    return render_template('view.html', user=user)


@app.route('/login', methods=['GET', 'POST'])
@add_visit_log
def login():
    session.pop('_flashes', None)
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        user = User.query.filter_by(login=login).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Успешный вход', 'info')
            return redirect(url_for('index'))
        else:
            flash('Неправильный пароль или логин', 'error')
            return render_template('login.html',  login=login, password=password)

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/create', methods=['GET', 'POST'])
@login_required
@check_rights
@add_visit_log
def create():
    session.pop('_flashes', None)

    roles = Role.query.all()
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        last_name = request.form['last_name']
        first_name = request.form['first_name']
        middle_name = request.form['middle_name']
        role_id = request.form['role_id']

        if not is_valid_password(password):
            flash('Недопустимый пароль', 'error')
            return render_template('create.html', login=login, password=password, last_name=last_name, first_name=first_name, middle_name=middle_name, roles=roles)

        if not (login and password and last_name and first_name and role_id and middle_name):
            flash('Все поля обязательны', 'error')
            return render_template('create.html', login=login, password=password, last_name=last_name, first_name=first_name, middle_name=middle_name, roles=roles)

        if User.query.filter_by(login=login).first():
            flash('Пользователь с таким именем уже существует', 'error')
            return render_template('create.html', login=login, password=password, last_name=last_name, first_name=first_name, middle_name=middle_name, roles=roles)

        user = User(
            login=login,
            password=generate_password_hash(password),
            last_name=last_name,
            first_name=first_name,
            middle_name=middle_name,
            role_id=role_id
        )
        db.session.add(user)
        db.session.commit()
        flash('Пользователь создан', 'success')
        return redirect(url_for('index'))

    return render_template('create.html', roles=roles)


@app.route('/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@add_visit_log
def edit(user_id):
    session.pop('_flashes', None)

    if user_id != current_user.id and current_user.role.name != 'admin':
        flash(ACCESS_DENIED, 'error')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.login = request.form['login']
        user.last_name = request.form['last_name']
        user.first_name = request.form['first_name']
        user.middle_name = request.form['middle_name']
        if request.form.get('role_id'):
            user.role_id = request.form['role_id']

        db.session.commit()
        flash('Пользователь изменен', 'success')
        return redirect(url_for('index'))

    roles = Role.query.all()
    return render_template('edit.html', user=user, roles=roles)


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
@add_visit_log
def change_password():
    session.pop('_flashes', None)
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not check_password_hash(current_user.password, old_password):
            flash('Неправильный старый пароль', 'error')
            return redirect(url_for('change_password'))

        if not is_valid_password(new_password):
            flash('Неправильный формат пароля', 'error')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('Пароли не совпадают', 'error')
            return redirect(url_for('change_password'))

        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()

        flash('Пароль изменен', 'success')
        return redirect(url_for('index'))

    return render_template('change_password.html')


@app.route('/delete/<int:user_id>', methods=['POST'])
@login_required
@check_rights
@add_visit_log
def delete(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('Пользователь удален', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        generate_defaults(db)

    app.run(debug=True)
