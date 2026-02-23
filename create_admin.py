from dotenv import load_dotenv
load_dotenv()

from werkzeug.security import generate_password_hash
from database.mongo import users_collection
from datetime import datetime

# Admin details
admin_email = "official.blockauth@gmail.com"
admin_username = "admin"
admin_password = "admin123"

# Check if admin already exists
existing_admin = users_collection.find_one({
    "email": admin_email
})

if existing_admin:

    print("Admin already exists")

    # OPTIONAL: ensure full_name exists
    users_collection.update_one(
        {"email": admin_email},
        {
            "$set": {
                "full_name": existing_admin.get("full_name", "System Administrator")
            }
        }
    )

else:

    users_collection.insert_one({

        "full_name": "System Administrator",

        "username": admin_username,

        "email": admin_email,

        "password": generate_password_hash(admin_password),

        "role": "admin",

        # ⭐ ADD THESE (IMPORTANT FOR YOUR SYSTEM)
        "genuine_scans": 0,
        "fake_scans": 0,
        "credibility_score": 100,

        "is_active": True,

        "created_at": datetime.utcnow()

    })

    print("Admin created successfully")
    print("Email:", admin_email)
    print("Password:", admin_password)