from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_required, login_user, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in succesfully.', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            flash('Wrong Password', category='error')
        flash('User does not exist.', category='error')        
    return render_template("login.html", user=current_user)

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('User already exists.', category='error')

        if len(email) < 4:
            flash('Email should be atleast 4 characters long.', category='error')

        elif len(first_name) < 2:
            flash('First Name should be atleast 2 characters long.', category='error')

        elif password1 != password2:
            flash('Passwords do not match.', category='error')

        elif len(password1) < 8:
            flash('Password should be atleast 8 characters long.', category='error')

        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True) #code changed here
            flash('User created succesfully.', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


