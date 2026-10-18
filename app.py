import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-super-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///portal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ----------------- Database Model -----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'student', 'alumni', 'campus'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Create database tables
with app.app_context():
    db.create_all()

# ----------------- Role Protection Decorator -----------------
def role_required(allowed_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in first.', 'warning')
                return redirect(url_for('login'))
            if session.get('role') != allowed_role:
                flash('Unauthorized access: You cannot view this dashboard.', 'danger')
                return redirect(url_for(f"{session.get('role')}_dashboard"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ----------------- Landing Page (Renders app.html first) -----------------
@app.route('/')
def index():
    return render_template('app.html')

# ----------------- Authentication Routes -----------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # If user is already logged in, send them to their role dashboard
    if 'user_id' in session:
        return redirect(url_for(f"{session['role']}_dashboard"))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password')
        role = request.form.get('role')

        # Basic validations
        if not all([name, email, password, role]):
            flash('All fields are required!', 'danger')
            return redirect(url_for('signup'))

        if role not in ['student', 'alumni', 'campus']:
            flash('Invalid role selected.', 'danger')
            return redirect(url_for('signup'))

        # Check existing user
        if User.query.filter_by(email=email).first():
            flash('An account with this email already exists.', 'warning')
            return redirect(url_for('signup'))

        # Create new user
        new_user = User(name=name, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, send them to their role dashboard
    if 'user_id' in session:
        return redirect(url_for(f"{session['role']}_dashboard"))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            # Save user session
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['role'] = user.role

            # Redirect dynamically based on registered role
            if user.role == 'student':
                return redirect(url_for('student_dashboard'))
            elif user.role == 'alumni':
                return redirect(url_for('alumni_dashboard'))
            elif user.role == 'campus':
                return redirect(url_for('campus_dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

# ----------------- Dashboards -----------------
@app.route('/student')
@role_required('student')
def student_dashboard():
    return render_template('student.html', user_name=session.get('user_name'))

@app.route('/alumni')
@role_required('alumni')
def alumni_dashboard():
    return render_template('alumni.html', user_name=session.get('user_name'))

@app.route('/campus')
@role_required('campus')
def campus_dashboard():
    return render_template('campus.html', user_name=session.get('user_name'))

# ----------------- Logout -----------------
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)