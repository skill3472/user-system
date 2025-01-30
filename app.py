from flask import Flask, render_template, request, redirect, url_for, flash, session
from dotenv import load_dotenv
import bcrypt as bc
import utils
import os
from datetime import timedelta

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET")
app.permanent_session_lifetime = timedelta(days=30)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/users')
def users():
    conn = utils.get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id_user, username FROM user")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    print(users)
    return render_template('users.html', users=users)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not request.form:
            return "No form data submitted!", 400
        username = request.form.get('username')
        password = request.form.get('password')
        password_repeat = request.form.get('password_repeat')
        if password != password_repeat:
            flash('The passwords you entered don\'t match!', 'error')
            return redirect(url_for('register'))
        salt = bc.gensalt()
        hashed_pw = bc.hashpw(password.encode('utf-8'), salt)
        utils.AddUser(username, hashed_pw)
        flash(f'The account {username} has been registered!', 'info')
        return redirect(url_for('index'))
    else:
        return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not request.form:
            return "No form data submitted!", 400
        username = request.form.get('username')
        password = request.form.get('password')
        persistSession = request.form.get('rememberMe')
        session.permanent = persistSession
        print(f'DEBUG: Request data is\n{request.form}')
        success = utils.CheckUser(username, password)
        if success:
            session['user'] = utils.GetUserID(username)
            flash('Logged in successfuly!', 'info')
            return redirect(url_for('index'))
        else:
            flash('The login and/or password you entered are incorrect.', 'error')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user' in session:
        session.pop('user', None)
        flash('You have been logged out.', 'info')
        return redirect(url_for('index'))
    else:
        flash('You\'re not logged in, you can\'t log out!', 'error')
        return redirect(url_for('index'))

@app.route("/profile")
def profile():
    if 'user' not in session:
        flash('You need to be logged in to view this page!', 'error')
        return redirect(url_for('login'))
    return render_template('profile.html')


if __name__ == '__main__':
    app.run(debug=True, host='192.168.1.34')