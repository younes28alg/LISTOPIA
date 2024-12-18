#imports
import flask
from flask import Flask ,render_template,redirect,request,session
from flask import url_for
from flask import Flask
from flask import Flask
import jinja2
from flask_scss import Scss
from jinja2 import Environment, PackageLoader, select_autoescape

from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from datetime import datetime
from jinja2 import Environment, PackageLoader, select_autoescape
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
#LOGIN






from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from datetime import datetime

# Initialize Flask App and other components
app = Flask(__name__, static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_FILE_DIR'] = './tmp'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    # Relationship: One user can have many tasks
    tasks = db.relationship('mytask', backref='user', lazy=True)

# Task Model
class mytask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)  # Task category
    priority = db.Column(db.Integer, default=1)  # 1: Low, 2: Medium, 3: High
    status = db.Column(db.String(20), default='in progress')  # 'in progress' or 'completed'
    created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Associate task with a user

    def __repr__(self) -> str:
        return f"Task {self.id}"

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms for registration and login
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    db.create_all()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    db.create_all()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/index')
@login_required
def index():
    tasks = mytask.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', tasks=tasks)

@app.route('/dashboard')
@login_required
def dashboard():
    tasks = mytask.query.filter_by(user_id=current_user.id).all()
    total_tasks = len(tasks)
    in_progress_count = sum(1 for task in tasks if task.status == 'in progress')
    completed_count = sum(1 for task in tasks if task.status == 'completed')
    return render_template('dashboard.html', total_tasks=total_tasks, in_progress_count=in_progress_count, completed_count=completed_count)

@app.route('/create-task', methods=['GET', 'POST'])
@login_required
def create_task():
    if request.method == "POST":
        title = request.form['title']
        content = request.form['content']
        category = request.form['category']
        priority = int(request.form['priority'])
        new_task = mytask(title=title, content=content, category=category, priority=priority, user_id=current_user.id)
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('create_task.html')

@app.route('/index/delete/<int:id>')
@login_required
def delete(id: int):
    task = mytask.query.get_or_404(id)
    if task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/index/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id: int):
    task = mytask.query.get_or_404(id)
    if task.user_id != current_user.id:
        return redirect(url_for('index'))
    if request.method == "POST":
        task.title = request.form['title']
        task.content = request.form['content']
        task.category = request.form['category']
        task.priority = int(request.form['priority'])
        task.status = request.form['status']
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edit.html', task=task)

@app.route('/tasks')
@login_required
def tasks():
    tasks = mytask.query.filter_by(user_id=current_user.id).order_by(mytask.created).all()
    return render_template('tasks.html', tasks=tasks)

@app.route('/index/toggle_status/<int:id>', methods=['POST'])
@login_required
def toggle_status(id: int):
    task = mytask.query.get_or_404(id)
    if task.user_id == current_user.id:
        task.status = 'completed' if task.status == 'in progress' else 'in progress'
        db.session.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)