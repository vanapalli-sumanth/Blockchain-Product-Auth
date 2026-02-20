from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

client = MongoClient(MONGO_URI)

# Explicit DB selection
db = client["fake_product_db"]

# Collections
users_collection = db["users"]
products_collection = db["products"]

# ✅ ADD THIS
verification_logs_collection = db["verification_logs"]
