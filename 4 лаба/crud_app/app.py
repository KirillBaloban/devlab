from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    first_name = db.Column(db.String(50))
    middle_name = db.Column(db.String(50))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    role = db.relationship('Role')
    creation_date = db.Column(db.DateTime, default=datetime.utcnow)


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))


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


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# Routes
@app.route('/')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)


@app.route('/view/<int:user_id>')
def view(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('view.html', user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']

        user = User.query.filter_by(login=login).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Успешный вход', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неправильный пароль или логин', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        last_name = request.form['last_name']
        first_name = request.form['first_name']
        middle_name = request.form['middle_name']
        role_id = request.form['role_id']

        if not is_valid_password(password):
            flash('Недопустимый пароль', 'error')
            return redirect(url_for('create'))

        if not (login and password and last_name and first_name and role_id):
            flash('Все поля обязательны', 'error')
            return redirect(url_for('create'))

        if User.query.filter_by(login=login).first():
            flash('Пользователь с таким именем уже существует', 'error')
            return redirect(url_for('create'))

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

    roles = Role.query.all()
    return render_template('create.html', roles=roles)


@app.route('/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.login = request.form['login']
        user.last_name = request.form['last_name']
        user.first_name = request.form['first_name']
        user.middle_name = request.form['middle_name']
        user.role_id = request.form['role_id']

        db.session.commit()
        flash('Пользователь изменен', 'success')
        return redirect(url_for('index'))

    roles = Role.query.all()
    return render_template('edit.html', user=user, roles=roles)


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
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
def delete(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('Пользователь удален', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = Role(**{
                'name': 'admin',
                'description': 'admin role'
            })
            db.session.add(admin_role)
            db.session.commit()

        default_user = User.query.filter_by(login='admin').first()
        if not default_user:
            default_password = generate_password_hash('admin')
            default_user = User(**{
                'login': 'admin',
                'password': default_password,
                'last_name': 'admin',
                'role_id': admin_role.id
            })
            db.session.add(default_user)
            db.session.commit()

    app.run(debug=True)
