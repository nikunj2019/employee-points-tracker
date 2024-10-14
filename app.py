from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash
from datetime import datetime
from flask_migrate import Migrate
from functools import wraps

# Import db from the separate db.py file
from db import db  

# Initialize the Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///employees.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'

# Initialize SQLAlchemy and Flask-Migrate
db.init_app(app)
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Import models after db is initialized
with app.app_context():
    from models import User, Employee, PointsHistory  # Import your models here

@app.before_request
def create_tables():
    db.create_all()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            return abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# Manager role required decorator (admin or manager can access)
def manage_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['admin', 'manager']:
            return abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    employees = Employee.query.filter_by(is_deleted=False).all()
    return render_template('read_only.html', employees=employees)

@app.route('/dashboard')
@login_required  # This ensures that only logged-in users can access the dashboard
def dashboard():
    employees = Employee.query.filter_by(is_deleted=False).all()  # Or other necessary logic
    return render_template('dashboard.html', employees=employees)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))  # Redirect to dashboard after login
        else:
            flash('Invalid username or password', 'danger')  # Provide feedback for invalid login
            return redirect(url_for('login'))  # Stay on login page if credentials are wrong

    return render_template('login.html')

@app.route('/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error = 'User already exists.'
        else:
            new_user = User(username=username, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('index'))

    return render_template('create_user.html', error=error)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
@admin_required
def change_password():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']

        user = User.query.filter_by(username=username).first()
        if not user:
            error = 'User not found.'
        else:
            user.set_password(new_password)
            db.session.commit()
            return redirect(url_for('index'))

    return render_template('change_password.html', error=error)

@app.route('/add_points/<int:id>', methods=['POST'])
@login_required
@manage_required
def add_points(id):
    employee = Employee.query.get_or_404(id)
    points = int(request.form['points'])
    comment = request.form.get('comment')

    if not comment:
        return "Comment is required", 400

    employee.points += points
    new_history = PointsHistory(points=points, employee_id=id, user_id=current_user.id, comment=comment)
    db.session.add(new_history)
    db.session.commit()

    return redirect(url_for('index'))

@app.route('/restore_employee/<int:id>', methods=['POST'])
@login_required
@admin_required
def restore_employee(id):
    employee = Employee.query.get_or_404(id)
    if employee.is_deleted:
        employee.is_deleted = False  # Restore the employee
        db.session.commit()
        flash(f'Employee {employee.name} has been restored.', 'success')
    else:
        flash(f'Employee {employee.name} is not deleted.', 'warning')
    
    return redirect(url_for('view_deleted_employees'))


@app.route('/remove_points/<int:id>', methods=['POST'])
@login_required
@manage_required
def remove_points(id):
    employee = Employee.query.get_or_404(id)
    points = int(request.form['points'])
    comment = request.form.get('comment')

    if not comment:
        return "Comment is required", 400

    employee.points -= abs(points)
    new_history = PointsHistory(points=-abs(points), employee_id=id, user_id=current_user.id, comment=comment)
    db.session.add(new_history)
    db.session.commit()

    return redirect(url_for('index'))

@app.route('/read_only_page')
def read_only_page():
    employees = Employee.query.filter_by(is_deleted=False).all()
    return render_template('read_only.html', employees=employees)

@app.route('/add_employee', methods=['POST'])
@login_required
def add_employee():
    name = request.form['name']
    new_employee = Employee(name=name)
    db.session.add(new_employee)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/redeem_points/<int:id>', methods=['POST'])
@login_required
@manage_required
def redeem_points(id):
    employee = Employee.query.get_or_404(id)
    reward = request.form.get('reward')

    reward_system = {
        '100': {'description': '$20 Gift Card', 'points': 100},
        '200': {'description': '4 Hours Off', 'points': 200},
        '300': {'description': '8 Hours Off (Full Day)', 'points': 300},
        '500': {'description': '$500 Bonus', 'points': 500}
    }

    if reward not in reward_system:
        return "Invalid reward selection", 400

    required_points = reward_system[reward]['points']

    if employee.points < required_points:
        return "Insufficient points for redemption", 400

    # Deduct points and add comment (if missing, provide a default comment)
    employee.points -= required_points
    comment = request.form.get('comment', 'Redeemed points for reward')

    new_history = PointsHistory(points=-required_points, employee_id=id, user_id=current_user.id, comment=comment)
    db.session.add(new_history)
    db.session.commit()

    return redirect(url_for('index'))

@app.route('/view_points_history/<int:id>')
@login_required
def view_points_history(id):
    employee = Employee.query.get_or_404(id)
    points_history = PointsHistory.query.filter_by(employee_id=id).all()
    return render_template('points_history.html', employee=employee, points_history=points_history)

@app.route('/view_deleted_employees')
@login_required
@manage_required
def view_deleted_employees():
    deleted_employees = Employee.query.filter_by(is_deleted=True).all()
    return render_template('view_deleted_employees.html', deleted_employees=deleted_employees)

@app.route('/soft_delete_employee/<int:id>', methods=['POST'])
@login_required
@admin_required
def soft_delete_employee(id):
    employee = Employee.query.get_or_404(id)
    employee.is_deleted = True
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()  # This logs the user out
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))  # Redirect to login page after logout


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
