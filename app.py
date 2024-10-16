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
@login_required
def dashboard():
    # If the user is Read-Only, redirect them to their points history
    if current_user.role == 'read-only':
        # Fetch the employee details of the Read-Only user
        employee = Employee.query.filter_by(id=current_user.employee_id).first()
        if employee:
            return redirect(url_for('view_points_history', employee_id=employee.id))
        else:
            return "No employee found for this user", 404

    # For other roles (admin, manager), display the regular dashboard
    employees = Employee.query.filter_by(is_deleted=False).all()
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

@app.route('/list_users')
@login_required
@admin_required  # Only admins can list users
def list_users():
    users = User.query.all()  # Fetch all users
    return render_template('list_users.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required  # Only admins can delete users
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    # Prevent the deletion of the currently logged-in user (self-deletion)
    if user.id == current_user.id:
        return "You cannot delete yourself.", 403

    db.session.delete(user)
    db.session.commit()

    return redirect(url_for('list_users'))

@app.route('/delete_points/<int:employee_id>/<int:points_id>', methods=['POST'])
@login_required
@admin_required
def delete_points(employee_id, points_id):
    # Fetch the employee and points record
    employee = Employee.query.get_or_404(employee_id)
    points = PointsHistory.query.get_or_404(points_id)
    
    # Adjust the employee's total points by subtracting the points being deleted
    employee.points -= points.points
    
    # Delete the points record
    db.session.delete(points)
    
    # Commit the changes to the database
    db.session.commit()
    
    # Redirect back to the points history page
    return redirect(url_for('view_points_history', employee_id=employee.id))

@app.route('/bulk_add_points', methods=['GET', 'POST'])
@login_required
@manage_required
def bulk_add_points():
    selected_employees = request.form.getlist('employees[]')  # Get the list of selected employees
    points_category = request.form.get('points_category')  # Get the selected points category
    comment = request.form.get('comment')  # Get the comment

    if not selected_employees:
        flash('Please select at least one employee.', 'danger')
        return redirect(url_for('bulk_add_page'))

    if not comment:
        flash('Please provide a comment.', 'danger')
        return redirect(url_for('bulk_add_page'))

    # Map the points_category to actual points values (ensure this matches your dropdown options)
    points_mapping = {
        '10': 10,
        '20': 20,
        '5': 5,
	'10': 10,
	'15': 15
    }

    points = points_mapping.get(points_category, 0)  # Get the corresponding points value

    for employee_id in selected_employees:
        employee = Employee.query.get(employee_id)
        if employee:
            # Add points to the employee
            employee.points += points
            new_history = PointsHistory(points=points, employee_id=employee.id, user_id=current_user.id, comment=comment)
            db.session.add(new_history)

    db.session.commit()
    flash(f'Points successfully added to selected employees.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/bulk_add_page', methods=['GET'])
@login_required
@manage_required
def bulk_add_page():
    employees = Employee.query.filter_by(is_deleted=False).all()
    return render_template('bulk_add_points.html', employees=employees)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    error = None
    success = None
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Verify current password
        if not current_user.check_password(current_password):
            error = 'Current password is incorrect.'
        elif new_password != confirm_password:
            error = 'New passwords do not match.'
        else:
            # Update password
            current_user.set_password(new_password)
            db.session.commit()
            success = 'Password changed successfully!'

    return render_template('change_password.html', error=error, success=success)

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

@app.route('/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']  # Get the role from the form
        employee_id = request.form['employee_id']  # Get the employee_id from the form

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error = 'User already exists.'
        else:
            # Create new user with the selected role and employee
            new_user = User(username=username, role=role, employee_id=employee_id)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('index'))

    # Fetch all employees to populate the dropdown
    employees = Employee.query.all()
    return render_template('create_user.html', error=error, employees=employees)


@app.route('/view_points_history/<int:employee_id>')
@login_required
def view_points_history(employee_id):
    # Fetch the employee and their points history
    employee = Employee.query.get_or_404(employee_id)
    
    # If the user is "read-only", ensure they are viewing their own points history
    if current_user.role == 'read-only' and current_user.employee_id != employee.id:
        return abort(403)  # Forbidden access if trying to access someone else's history

    points_history = PointsHistory.query.filter_by(employee_id=employee_id).all()

    return render_template('view_points_history.html', employee=employee, points_history=points_history)

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
