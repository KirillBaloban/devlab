from flask import Flask, render_template, redirect, url_for, request, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required

app = Flask(__name__)
app.secret_key = 'supersecretkey'

login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin):
    def __init__(self, id):
        self.id = id


users = {'user': {'password': 'qwerty'}}


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember')

        if username in users and users[username]['password'] == password:
            user = User(username)
            login_user(user, remember=remember)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', message='Неправильный логин или пароль.')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html')


@app.route('/visits')
def visits():
    session['visits'] = session.get('visits', 0) + 1
    return "Total visits: {}".format(session['visits'])


if __name__ == '__main__':
    app.run(debug=True)
