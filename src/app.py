#!/usr/bin/python

# Flask
from flask import Flask, render_template, jsonify, request, flash, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_login import login_required, current_user, login_user, logout_user
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from werkzeug import secure_filename
from flask_sqlalchemy import SQLAlchemy
# OS
import os
# Config
import config
# Sessions
from uuid import uuid4
# Time
import time
# Forms
from forms import LoginForm, RegisterForm


# APP
app = Flask(__name__)
app.config.from_object("config.DevelopmentConfig")
# Bcrypt
bcrypt = Bcrypt(app)
# Bootstrap
Bootstrap(app)
# Login
login_manager = LoginManager()
login_manager.init_app(app)
# DB
db = SQLAlchemy(app)

# Static path
static_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"))


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter(User.id == str(user_id)).first()


# http://flask.pocoo.org/snippets/62/
from urllib.parse import urlparse, urljoin
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


# LANDING
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    form = RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            print('Getting user data')
            user = User(
                name=request.form['username'],
                email=request.form['email'],
                password=request.form['password'],
                forename=request.form['forename'],
                surname=request.form['surname'],
            )
            print('Adding user')
            db.session.add(user)
            print('Commit')
            db.session.commit()
            print('Login')
            login_user(user)
            return redirect(url_for('.dashboard'))
        else:
            error = 'Invalid data'
    return render_template('register.html', form=form, error=error)


# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    form = LoginForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(name=request.form['username']).first()
            if user is not None and bcrypt.check_password_hash(
                    user.password, request.form['password']
                    ):
                login_user(user)
                flash('You were logged in.')
                # https://flask-login.readthedocs.io/en/latest/#how-it-works
                next = request.args.get('next')
                if not is_safe_url(next):
                    return abort(400)
                return redirect(next or url_for('.dashboard'))
            else:
                error = 'Invalid username or password'
    return render_template('login.html', form=form, error=error)


# LOGOUT
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You were logged out.')
    return redirect(url_for('.index'))


# DASHBOARD
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.name)


class User(db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String)
    forename = db.Column(db.String, nullable=False)
    surname = db.Column(db.String, nullable=False)

    def __init__(self, name, email, password, forename, surname):
        self.name = name
        self.email = email
        # Change the number of rounds (second argument) until it takes between 0.25 and 0.5 seconds to run
        self.password = bcrypt.generate_password_hash(password, 12)
        self.forename = forename
        self.surname = surname

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return '<name - {}>'.format(self.name)


if __name__ == '__main__':
    # RUN
    app.run(host='0.0.0.0')