from dotenv import load_dotenv
load_dotenv()

from werkzeug.security import generate_password_hash
from database.mongo import users_collection
from datetime import datetime

# Admin details
admin_email = "admin@gmail.com"
admin_username = "admin"
admin_password = "admin123"

# Check if admin already exists by email
if users_collection.find_one({"email": admin_email}):

    print("Admin already exists")

else:

    result = users_collection.insert_one({

        "full_name": "System Administrator",

        "username": admin_username,

        "email": admin_email,

        "password": generate_password_hash(admin_password),

        "role": "admin",

        "is_active": True,

        "created_at": datetime.utcnow()

    })

    print("Admin created successfully")
    print("Email:", admin_email)
    print("Password:", admin_password)
