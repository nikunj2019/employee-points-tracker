from app import db, app  # Import app to use app context
from models import User
from werkzeug.security import generate_password_hash

# Define admin details
admin_username = 'admin'
admin_password = 'adminpassword'
admin_role = 'admin'

# Create an admin user
admin_user = User(username=admin_username, role=admin_role)
admin_user.set_password(admin_password)

# Run the following code within the Flask application context
with app.app_context():
    db.session.begin()
    db.session.add(admin_user)
    db.session.commit()

print(f"Admin user '{admin_username}' has been created successfully.")
