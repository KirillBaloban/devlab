from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

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
    return render_template('index.html', current_user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember')
        if username in users and users[username]['password'] == password:
            user = User(username)
            login_user(user, remember=remember)
            flash('Вы успешно аутентифицированы.', 'success')
            endpoint = request.args.get('return_endpoint')
            if endpoint == 'secret':
                return redirect(url_for('secret'))
            return redirect(url_for('index'))
        else:
            flash('Неправильный логин или пароль.','danger')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html', current_user=current_user)

@app.route('/visits')
def visits():
    if current_user.is_authenticated:
        session['visits_authenticated'] = session.get('visits_authenticated', 0) + 1
        return render_template('visits.html', visits=session['visits_authenticated'])
    
    session['visits_unauthenticated'] = session.get('visits_unauthenticated', 0) + 1
    return render_template('visits.html', visits=session['visits_unauthenticated'])

@app.before_request
def before_request():
    if request.endpoint in ['secret'] and not current_user.is_authenticated:
        flash('Вы должны сначала авторизоваться', 'warning')
        return redirect(url_for('login', return_endpoint=request.endpoint))

if __name__ == '__main__':
    app.run(debug=True)