from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db   ##means from __init__.py import db
from flask_login import login_user, login_required, logout_user, current_user
import os

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        user = request.args.get('user')
        if user == "admin":
            return render_template('admin_home.html', user="admin")
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if email == "harsh@admin":
            if password == "admin@123":
                return render_template('admin_home.html', user="admin")

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
    print("USER is ===============",current_user)
    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    user = request.args.get('user')
    if user == "admin":
        return render_template("login.html")
    else:
        logout_user()
        return redirect(url_for('auth.login'))

@auth.route('/display_encoded_images')
def display_encoded_images():
    encoded_images_list= os.listdir("website/static/encoded_images")
    return render_template('display_encoded_images.html', list_files=encoded_images_list, user=current_user)


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)

@auth.route('/users_list', methods=['GET', 'POST'])
def users_details():
    users = User.query.all()
    return render_template("user_details.html", user="admin", users=users)

@auth.route('/edit_users_list', methods=['GET', 'POST'])
def edit_users_details():
    if request.method == "GET":
        email = request.args.get('email')
        users = User.query.filter_by(email=email).first()
        # print(users.first_name) 
        return render_template("edit_user_details.html", user="admin", users=users)
    if request.method == "POST":
        name = request.form.get('name')
        email_id = request.form.get('email_id')
        email = request.form.get('email')
        users = User.query.filter_by(email=email).first()
        print(users.email)
        users.email = email_id
        users.first_name = name
        db.session.commit()
        flash("Changes updated!")
        users = User.query.all()
        return render_template("user_details.html", user="admin", users=users)
    
@auth.route('/delete', methods=['GET', 'POST'])
def delete():
    if request.method == "GET":
        email = request.args.get('email')
        users = User.query.filter_by(email=email).delete()
        db.session.commit()
        flash("Changes updated!")
        users = User.query.all()
        return render_template("user_details.html", user="admin", users=users)