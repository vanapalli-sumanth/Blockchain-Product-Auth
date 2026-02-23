from flask import Flask, render_template, request, redirect, session, url_for, abort
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from database.mongo import users_collection, products_collection, verification_logs_collection
from blockchain.web3_config import add_product
from blockchain.web3_config import verify_product as blockchain_verify_product
from utils.qr_generator import generate_qr
from datetime import datetime
import pytz
import os
import uuid
from flask import send_file
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as grequests
from flask import flash
import pandas as pd
from flask import make_response
from io import BytesIO
import hashlib
from utils.scratch_generator import generate_scratch_code
from utils.qr_generator import generate_qr
from database.mongo import product_units_collection
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from openpyxl import Workbook
from openpyxl.drawing.image import Image as XLImage
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

IST = pytz.timezone("Asia/Kolkata")

def send_approval_email(to_email, full_name):

    sender = os.getenv("EMAIL_USER")
    password = os.getenv("EMAIL_PASS")
    base_url = os.getenv("APP_BASE_URL")

    # SAFETY CHECK
    if not sender or not password or not base_url:
        print("Email config missing:",
              sender, password, base_url)
        return

    try:

        login_url = base_url + "/login"

        subject = "Your Manufacturer Account has been Approved ✅"

        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">

            <h2 style="color:#0b2a6e;">
                Your Manufacturer Account is Approved 🎉
            </h2>

            <p>Hello <b>{full_name}</b>,</p>

            <p>
                Your manufacturer account has been approved by the admin.
            </p>

            <a href="{login_url}"
            style="
                background:#0b2a6e;
                color:white;
                padding:12px 24px;
                text-decoration:none;
                border-radius:6px;
                font-weight:bold;
                display:inline-block;
            ">
                Login Now
            </a>

            <br><br>

            <p>{login_url}</p>

        </body>
        </html>
        """

        msg = MIMEMultipart("alternative")
        msg["From"] = sender
        msg["To"] = to_email
        msg["Subject"] = subject

        msg.attach(MIMEText(html_body, "html"))

        # FIX 1: use timeout
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=30)

        # FIX 2: ehlo required for Render
        server.ehlo()

        # FIX 3: starttls with ehlo again
        server.starttls()
        server.ehlo()

        # LOGIN
        server.login(sender, password)

        # SEND
        server.sendmail(sender, to_email, msg.as_string())

        # CLOSE
        server.quit()

        print("Approval email sent successfully to", to_email)

    except Exception as e:
        print("EMAIL FAILED:", str(e))

def get_location_from_gps(lat, lon):

    try:

        url = "https://nominatim.openstreetmap.org/reverse"

        params = {
            "format": "json",
            "lat": lat,
            "lon": lon,
            "zoom": 18,
            "addressdetails": 1
        }

        headers = {
            "User-Agent": "BlockAuthApp/1.0"
        }

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=5
        )

        data = response.json()

        address = data.get("address", {})

        city = (
            address.get("city")
            or address.get("town")
            or address.get("village")
            or address.get("county")
            or address.get("state_district")
        )

        country = address.get("country")

        if city and country:
            return f"{city}, {country}"

        elif country:
            return country

        else:
            return "Unknown"

    except Exception as e:

        print("GPS Location Error:", e)

        return "Unknown"
    
# ---------- AUTH GUARD ----------
def login_required(role=None):

    if "user" not in session:
        flash("Please login first", "warning")
        return False

    user = users_collection.find_one({
        "username": session.get("user")
    })

    if not user:

        session.clear()

        flash("Session expired", "warning")

        return False

    # BLOCK CHECK
    if user.get("is_active") == False:

        session.clear()

        flash("Your account has been blocked by admin", "danger")

        return False

    session["full_name"] = user.get("full_name", user["username"])

    if role and user.get("role") != role:

        flash("Unauthorized access", "danger")

        return False

    return True

# ---------- HOME ----------
@app.route("/")
def home():
    return render_template("home.html")

# ---------- GOOGLE LOGIN ----------
@app.route("/google-login")
def google_login():

    google_provider_cfg = requests.get(
        os.getenv("GOOGLE_DISCOVERY_URL")
    ).json()

    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # FIXED redirect URI
    if "onrender.com" in request.host:
        redirect_uri = "https://blockchain-product-auth.onrender.com/google-auth"
    else:
        redirect_uri = "http://127.0.0.1:5000/google-auth"

    request_uri = requests.Request(
        "GET",
        authorization_endpoint,
        params={
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "response_type": "code",
        },
    ).prepare().url

    return redirect(request_uri)

# ---------- GOOGLE AUTH CALLBACK ----------
@app.route("/google-auth")
def google_auth():

    code = request.args.get("code")

    if not code:
        flash("Google login failed: No code received", "danger")
        return redirect("/login")

    google_provider_cfg = requests.get(
        os.getenv("GOOGLE_DISCOVERY_URL")
    ).json()

    token_endpoint = google_provider_cfg["token_endpoint"]

    if "onrender.com" in request.host:
        redirect_uri = "https://blockchain-product-auth.onrender.com/google-auth"
    else:
        redirect_uri = "http://127.0.0.1:5000/google-auth"

    token_response = requests.post(
        token_endpoint,
        headers={
            "Content-Type": "application/x-www-form-urlencoded"
        },
        data={
            "code": code,
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
    )

    token_json = token_response.json()

    # FIX: check access_token exists
    if "access_token" not in token_json:

        print("GOOGLE TOKEN ERROR:", token_json)

        flash("Google login failed. Please try again.", "danger")

        return redirect("/login")

    access_token = token_json["access_token"]

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]

    userinfo_response = requests.get(
        userinfo_endpoint,
        headers={
            "Authorization": f"Bearer {access_token}"
        },
    )

    userinfo = userinfo_response.json()

    email = userinfo.get("email")
    name = userinfo.get("name")

    if not email:
        flash("Google login failed. No email received.", "danger")
        return redirect("/login")

    user = users_collection.find_one({"email": email})

    if not user:

        session["google_name"] = name
        session["google_email"] = email

        return redirect("/select-role")

    if not user.get("is_active", True):

        session.clear()
        flash("Your account has been blocked", "danger")
        return redirect("/login")

    session["user"] = user["username"]
    session["full_name"] = user["full_name"]
    session["role"] = user["role"]

    if user["role"] == "manufacturer":
        return redirect("/manufacturer/dashboard")

    elif user["role"] == "admin":
        return redirect("/admin/dashboard")

    return redirect("/customer/dashboard")

# ---------- REGISTER ----------
@app.route("/register", methods=["GET","POST"])
def register():

    if request.method == "POST":

        email = request.form["email"].lower()
        username = request.form["username"]
        role = request.form["role"]

        # check email exists
        if users_collection.find_one({"email": email}):
            flash("Email already registered", "danger")
            return redirect("/register")

        # check username exists
        if users_collection.find_one({"username": username}):
            flash("Username already taken", "danger")
            return redirect("/register")

        # ⭐ approval logic
        is_approved = False if role == "manufacturer" else True

        users_collection.insert_one({

            "full_name": request.form["full_name"],
            "username": username,
            "email": email,
            "password": generate_password_hash(
                request.form["password"]
            ),
            "role": role,

            "genuine_scans": 0,
            "fake_scans": 0,
            "credibility_score": 100,

            "is_active": True,

            # ⭐ NEW FIELD
            "is_approved": is_approved,

            "created_at": datetime.utcnow()
        })

        flash(
            "Account created. Wait for admin approval."
            if role == "manufacturer"
            else "Account created successfully",
            "success"
        )

        return redirect("/login")

    return render_template("register.html")

# ---------- SELECT ROLE ----------
@app.route("/select-role", methods=["GET", "POST"])
def select_role():

    if "google_email" not in session:
        flash("Session expired", "warning")
        return redirect("/login")

    if request.method == "POST":

        role = request.form["role"]

        email = session["google_email"]
        name = session["google_name"]

        username = email.split("@")[0]

        is_approved = False if role == "manufacturer" else True

        users_collection.insert_one({

            "full_name": name,
            "username": username,
            "email": email,
            "password": None,
            "role": role,

            "genuine_scans": 0,
            "fake_scans": 0,
            "credibility_score": 100,

            "is_active": True,

            # ⭐ APPROVAL FIELD
            "is_approved": is_approved,

            "created_at": datetime.utcnow()
        })

        session["user"] = username
        session["full_name"] = name
        session["role"] = role

        session.pop("google_email", None)
        session.pop("google_name", None)

        if role == "manufacturer":
            return redirect("/manufacturer/dashboard")

        return redirect("/customer/dashboard")

    return render_template("select_role.html")

# ---------- LOGIN ----------
# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].lower().strip()
        password = request.form["password"]

        user = users_collection.find_one({"email": email})

        # USER NOT FOUND
        if not user:
            flash("Email not registered", "danger")
            return redirect("/login")

        # BLOCK CHECK
        if not user.get("is_active", True):

            session.clear()

            flash("Your account has been blocked by admin", "danger")

            return redirect("/login")

        # PASSWORD CHECK
        if user.get("password"):

            if not check_password_hash(user["password"], password):

                flash("Incorrect password", "danger")

                return redirect("/login")

        # SET SESSION
        session["user"] = user["username"]
        session["full_name"] = user.get("full_name", user["username"])
        session["role"] = user["role"]

        # ---------- MANUFACTURER ----------
        if user["role"] == "manufacturer":

            # NOT APPROVED → show pending page
            if not user.get("is_approved", False):
                return render_template("manufacturer_pending.html")

            # APPROVED → dashboard
            flash("Login successful", "success")

            return redirect("/manufacturer/dashboard")

        # ---------- ADMIN ----------
        elif user["role"] == "admin":

            flash("Admin login successful", "success")

            return redirect("/admin/dashboard")

        # ---------- CUSTOMER ----------
        else:

            flash("Login successful", "success")

            return redirect("/customer/dashboard")

    return render_template("login.html")

# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for("login"))

# ---------- CALCULATE MANUFACTURER CREDIBILITY ----------
def calculate_manufacturer_credibility(username):

    products = list(products_collection.find({
        "added_by": username
    }))

    if not products:
        return 100

    product_ids = [p["product_id"] for p in products]

    logs = list(verification_logs_collection.find({
        "product_id": {"$in": product_ids}
    }))

    genuine = sum(
        1 for log in logs
        if log.get("status") == "genuine"
    )

    fake = sum(
        1 for log in logs
        if log.get("status") == "fake"
    )

    duplicate = sum(
        1 for log in logs
        if log.get("status") == "duplicate"
    )

    already_verified = sum(
        1 for log in logs
        if log.get("status") == "already_verified"
    )

    total = genuine + fake + duplicate + already_verified

    if total == 0:
        return 100

    score = (
        (genuine * 2)
        + (already_verified * 1)
        - (fake * 15)
        - (duplicate * 10)
    )

    credibility = 100 + score

    credibility = max(0, min(100, credibility))

    return credibility

# ---------- MANUFACTURER DASHBOARD ----------
@app.route("/manufacturer/dashboard")
def manufacturer_dashboard():

    if not login_required("manufacturer"):
        abort(403)

    user = users_collection.find_one({
        "username": session["user"]
    })

    if not user.get("is_approved", False):
        return render_template("manufacturer_pending.html")

    # ⭐ CALCULATE REAL CREDIBILITY
    manufacturer_credibility = calculate_manufacturer_credibility(
        session["user"]
    )

    # ⭐ UPDATE IN DATABASE
    users_collection.update_one(
        {"username": session["user"]},
        {"$set": {
            "credibility_score": manufacturer_credibility
        }}
    )

    # ---------- GET PRODUCTS ----------
    products_cursor = products_collection.find({
        "added_by": session["user"]
    }).sort("created_at", -1)

    products = []

    for p in products_cursor:

        utc = p.get("created_at")

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            p["created_at_ist"] = utc.astimezone(IST)

        products.append(p)

    return render_template(
        "manufacturer_dashboard.html",
        products=products,
        manufacturer_credibility=manufacturer_credibility,
        manufacturer_name=session.get("full_name")
    )

# ---------- MANUFACTURER ADD PRODUCT ----------
@app.route("/manufacturer/add-product", methods=["GET", "POST"])
def add_product_route():

    # ---------- LOGIN CHECK ----------
    if not login_required("manufacturer"):
        abort(403)

    # ---------- GET USER ----------
    user = users_collection.find_one({
        "username": session["user"]
    })

    if not user:

        session.clear()
        flash("Session expired. Please login again.", "danger")
        return redirect("/login")

    # ---------- ADMIN APPROVAL CHECK ----------
    if not user.get("is_approved", False):

        flash(
            "Your manufacturer account is waiting for admin approval.",
            "warning"
        )
        return redirect("/manufacturer/dashboard")

    # ---------- LOAD PAGE ----------
    if request.method == "GET":

        return render_template("add_product.html")

    try:

        # ---------- FORM DATA ----------
        name = request.form["name"].strip()
        brand = request.form["brand"].strip()
        quantity = int(request.form["quantity"])

        product_id = request.form.get("product_id")

        if not product_id:

            product_id = "PROD-" + uuid.uuid4().hex[:8].upper()

        # ---------- CHECK DUPLICATE ----------
        if products_collection.find_one({
            "product_id": product_id
        }):

            flash("Product ID already exists", "danger")
            return redirect("/manufacturer/add-product")

        manufacturer_username = session["user"]
        manufacturer_full_name = user["full_name"]

        # ---------- BLOCKCHAIN REGISTRATION ----------
        secure_token = uuid.uuid4().hex

        tx_hash = add_product(
            product_id,
            manufacturer_username,
            secure_token
        )

        # ---------- CREATED DATE (IST) ----------
        created_at_utc = datetime.utcnow()

        created_at_ist = created_at_utc.replace(
            tzinfo=pytz.utc
        ).astimezone(IST)

        created_at_str = created_at_ist.strftime(
            "%d %b %Y, %I:%M %p"
        )

        # ---------- SAVE PRODUCT ----------
        products_collection.insert_one({

            "product_id": product_id,

            "name": name,

            "added_by": manufacturer_username,

            "manufacturer_username": manufacturer_username,

            "manufacturer_name": manufacturer_full_name,

            "manufacturer_brand": brand,

            "tx_hash": tx_hash,

            "quantity": quantity,

            "secure_token": secure_token,

            "credibility_score": 100,

            "is_active": True,

            "created_at": created_at_utc

        })

        # ---------- CREATE PRODUCT UNITS ----------
        created_units = []

        for i in range(quantity):

            unit_id = "UNIT-" + uuid.uuid4().hex[:12].upper()

            scratch_plain = generate_scratch_code().strip().upper()

            scratch_hash = hashlib.sha256(
                scratch_plain.encode()
            ).hexdigest()

            qr = generate_qr(unit_id, scratch_plain)

            product_units_collection.insert_one({

                "unit_id": unit_id,

                "product_id": product_id,

                "manufacturer": manufacturer_username,

                "scratch_plain": scratch_plain,

                "scratch_hash": scratch_hash,

                "secure_token": qr["secure_token"],

                "signature": qr["signature"],

                "qr_code": qr["qr_path"],

                "is_used": False,

                "owner_username": None,

                "verify_count": 0,

                "created_at": created_at_utc,

                "last_verified_at": None,

                "verification_history": []

            })

            created_units.append({

                "unit_id": unit_id,

                "scratch": scratch_plain,

                "qr": qr["qr_path"]

            })

        # ---------- SUCCESS PAGE ----------
        return render_template(

            "product_created.html",

            product_id=product_id,

            units=created_units,

            manufacturer_name=manufacturer_full_name,

            created_at=created_at_str

        )

    except Exception as e:

        print("ADD PRODUCT ERROR:", e)

        flash("Failed to create product", "danger")

        return redirect("/manufacturer/dashboard")

# ---------- MANUFACTURER DELETE PRODUCT ----------
@app.route("/manufacturer/delete/<product_id>", methods=["POST"])
def manufacturer_delete_product(product_id):

    if "user" not in session:
        abort(403)

    role = session.get("role")
    username = session.get("user")

    if role not in ["manufacturer", "admin"]:
        abort(403)

    # ---------- FIND PRODUCT ----------
    if role == "manufacturer":

        product = products_collection.find_one({
            "product_id": product_id,
            "added_by": username
        })

    else:

        product = products_collection.find_one({
            "product_id": product_id
        })

    if not product:

        flash("Product not found or unauthorized", "danger")

        if role == "admin":
            return redirect("/admin/products")
        else:
            return redirect("/manufacturer/dashboard")

    # ---------- CHECK OWNED UNITS ----------
    owned_units_count = product_units_collection.count_documents({
        "product_id": product_id,
        "owner_username": {"$ne": None}
    })

    unused_units_count = product_units_collection.count_documents({
        "product_id": product_id,
        "owner_username": None
    })

    # ---------- DELETE ONLY UNUSED UNITS ----------
    if unused_units_count > 0:

        product_units_collection.delete_many({
            "product_id": product_id,
            "owner_username": None
        })

        verification_logs_collection.delete_many({
            "product_id": product_id,
            "owner_username": None
        })

    # ---------- IF OWNED UNITS EXIST → SOFT DELETE ----------
    if owned_units_count > 0:

        products_collection.update_one(
            {"product_id": product_id},
            {
                "$set": {
                    "is_active": False,
                    "deleted_at": datetime.utcnow(),
                    "quantity": owned_units_count
                }
            }
        )

        flash(
            f"Product deleted safely. {owned_units_count} owned units preserved.",
            "warning"
        )

    else:

        # NO OWNED UNITS → FULL DELETE SAFE
        verification_logs_collection.delete_many({
            "product_id": product_id
        })

        products_collection.delete_one({
            "product_id": product_id
        })

        flash("Product and all units deleted successfully", "success")

    # ---------- REDIRECT ----------
    if role == "admin":
        return redirect(request.referrer)

    return redirect("/manufacturer/dashboard")

# ---------- MANUFACTURER PRODUCT LOGS ----------
@app.route("/manufacturer/product-logs/<product_id>")
def manufacturer_product_logs(product_id):

    # Must be logged in
    if "user" not in session:
        abort(403)

    role = session.get("role")
    username = session.get("user")

    if role not in ["manufacturer", "admin"]:
        abort(403)

    # Manufacturer → only own product
    if role == "manufacturer":

        product = products_collection.find_one({
            "product_id": product_id,
            "added_by": username
        })

    # Admin → allow any product
    else:

        product = products_collection.find_one({
            "product_id": product_id
        })

    if not product:
        flash("Access denied", "danger")

        if role == "admin":
            return redirect("/admin/manufacturers")
        else:
            return redirect("/manufacturer/dashboard")

    # Convert product date
    if product.get("created_at"):
        product["created_at_ist"] = product["created_at"]\
            .replace(tzinfo=pytz.utc)\
            .astimezone(IST)

    # Get logs
    logs_cursor = verification_logs_collection.find({
        "product_id": product_id
    }).sort("date", -1)

    logs = []

    for log in logs_cursor:

        if log.get("date"):
            log["ist_date"] = log["date"]\
                .replace(tzinfo=pytz.utc)\
                .astimezone(IST)

        # Get scratch code
        unit = product_units_collection.find_one({
            "unit_id": log.get("unit_id")
        })

        log["scratch_plain"] = unit.get("scratch_plain") if unit else "-"

        logs.append(log)

    return render_template(
        "manufacturer_product_logs.html",
        product=product,
        logs=logs,
        viewing_as_admin=(role == "admin")
    )

# ---------- MANUFACTURER UNIT LOGS ----------
@app.route("/manufacturer/unit-logs/<unit_id>")
def manufacturer_unit_logs(unit_id):

    if "user" not in session:
        abort(403)

    role = session.get("role")
    username = session.get("user")

    if role not in ["manufacturer", "admin"]:
        abort(403)

    # Manufacturer → only own unit
    if role == "manufacturer":

        unit = product_units_collection.find_one({
            "unit_id": unit_id,
            "manufacturer": username
        })

    # Admin → allow all
    else:

        unit = product_units_collection.find_one({
            "unit_id": unit_id
        })

    if not unit:
        flash("Access denied", "danger")

        if role == "admin":
            return redirect("/admin/manufacturers")
        else:
            return redirect("/manufacturer/dashboard")

    product = products_collection.find_one({
        "product_id": unit["product_id"]
    })

    # Convert dates
    if unit.get("created_at"):
        unit["created_at_ist"] = unit["created_at"]\
            .replace(tzinfo=pytz.utc)\
            .astimezone(IST)

    if unit.get("last_verified_at"):
        unit["owned_at_ist"] = unit["last_verified_at"]\
            .replace(tzinfo=pytz.utc)\
            .astimezone(IST)

    if product and product.get("created_at"):
        product["created_at_ist"] = product["created_at"]\
            .replace(tzinfo=pytz.utc)\
            .astimezone(IST)

    # Logs
    logs_cursor = verification_logs_collection.find({
        "unit_id": unit_id
    }).sort("date", -1)

    logs = []

    for log in logs_cursor:

        if log.get("date"):
            log["ist_date"] = log["date"]\
                .replace(tzinfo=pytz.utc)\
                .astimezone(IST)

        logs.append(log)

    return render_template(
        "manufacturer_unit_logs.html",
        unit=unit,
        product=product,
        logs=logs,
        viewing_as_admin=(role == "admin")
    )

# ---------- DELETE UNIT ----------
@app.route("/manufacturer/delete-unit/<unit_id>", methods=["POST"])
def delete_unit(unit_id):

    if "user" not in session:
        abort(403)

    role = session.get("role")
    username = session.get("user")

    if role not in ["manufacturer", "admin"]:
        abort(403)

    # Get unit
    if role == "manufacturer":
        unit = product_units_collection.find_one({
            "unit_id": unit_id,
            "manufacturer": username
        })
    else:
        unit = product_units_collection.find_one({
            "unit_id": unit_id
        })

    if not unit:
        flash("Unit not found or unauthorized", "danger")
        return redirect(request.referrer)

    # 🚫 BLOCK DELETE IF OWNED
    if unit.get("owner_username"):
        flash(
            f"Cannot delete Unit {unit_id} because it is owned by customer '{unit.get('owner_username')}'",
            "danger"
        )
        return redirect(request.referrer)

    product_id = unit["product_id"]

    # SAFE DELETE (only unused units)
    product_units_collection.delete_one({
        "unit_id": unit_id
    })

    verification_logs_collection.delete_many({
        "unit_id": unit_id
    })

    remaining_units = product_units_collection.count_documents({
        "product_id": product_id
    })

    products_collection.update_one(
        {"product_id": product_id},
        {"$set": {"quantity": remaining_units}}
    )

    flash("Unit deleted successfully", "success")

    return redirect(request.referrer)

# ---------- MANUFACTURER EXPORT PRODUCT LOGS ----------
@app.route("/manufacturer/export-logs-excel/<product_id>")
def export_logs_excel(product_id):

    if not login_required("manufacturer"):
        abort(403)

    logs = list(
        verification_logs_collection.find({
            "product_id": product_id
        }).sort("date", -1)
    )

    product = products_collection.find_one({
        "product_id": product_id
    })

    data = []

    for log in logs:

        utc = log.get("date")

        ist_time = ""

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            ist_time = utc.astimezone(IST).strftime(
                "%d %b %Y %I:%M %p"
            )

        # ⭐ FETCH SCRATCH FROM UNITS COLLECTION
        unit = product_units_collection.find_one({
            "unit_id": log.get("unit_id")
        })

        scratch_code = unit.get("scratch_plain") if unit else "-"

        data.append({

            "Product ID": log.get("product_id"),

            "Product Name": product.get("name"),

            "Brand": log.get("manufacturer_brand"),

            "Unit ID": log.get("unit_id"),

            "User": log.get("username"),

            "Owner": log.get("owner_username") or "Not claimed",

            # ⭐ NOW SHOW REAL SCRATCH
            "Scratch": scratch_code,

            "Blockchain Match":
                "Matched" if log.get("match_status") == "matched"
                else "Mismatch",

            "Verification Status": log.get("status"),

            "Location": log.get("location"),

            "IP Address": log.get("ip_address"),

            "Date (IST)": ist_time
        })

    df = pd.DataFrame(data)

    output = BytesIO()

    df.to_excel(output, index=False, engine="openpyxl")

    output.seek(0)

    response = make_response(output.read())

    response.headers["Content-Disposition"] = \
        f"attachment; filename={product_id}_verification_logs.xlsx"

    response.headers["Content-Type"] = \
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return response

# ---------- EXPORT MANUFACTURER DASHBOARD TABLE TO EXCEL ----------
@app.route("/manufacturer/export-products-excel")
def export_products_excel():

    if not login_required("manufacturer"):
        abort(403)

    products = list(products_collection.find({
        "added_by": session["user"]
    }).sort("created_at", -1))

    data = []

    for p in products:

        # Convert date to IST
        utc_time = p.get("created_at")

        ist_time = ""

        if utc_time:
            utc_time = utc_time.replace(tzinfo=pytz.utc)
            ist_time = utc_time.astimezone(IST).strftime(
                "%d %b %Y %I:%M %p"
            )

        data.append({

            "Product ID": p.get("product_id"),

            "Name": p.get("name"),

            "Brand": p.get("manufacturer_brand"),

            "Blockchain Tx Hash": p.get("tx_hash"),

            "Quantity": p.get("quantity"),

            "Added Date": ist_time

        })

    df = pd.DataFrame(data)

    output = BytesIO()

    df.to_excel(
        output,
        index=False,
        engine="openpyxl"
    )

    output.seek(0)

    response = make_response(output.read())

    response.headers[
        "Content-Disposition"
    ] = "attachment; filename=manufacturer_dashboard.xlsx"

    response.headers[
        "Content-Type"
    ] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return response

# ---------- MANUFACTURER PRODUCT UNITS ----------
@app.route("/manufacturer/product-units/<product_id>")
def manufacturer_product_units(product_id):

    if "user" not in session:
        abort(403)

    role = session.get("role")

    if role not in ["manufacturer", "admin"]:
        abort(403)

    # If manufacturer → only own products
    if role == "manufacturer":

        product = products_collection.find_one({
            "product_id": product_id,
            "added_by": session["user"]
        })

    else:
        # admin → allow all
        product = products_collection.find_one({
            "product_id": product_id
        })

    if not product:
        flash("Access denied", "danger")
        return redirect("/admin/manufacturers")

    units = list(product_units_collection.find({
        "product_id": product_id
    }))

    return render_template(
        "manufacturer_units.html",
        units=units,
        product=product,
        viewing_as_admin=(role == "admin")
    )

# ---------- EXPORT PRODUCT UNITS EXCEL ----------
from openpyxl import Workbook
from openpyxl.drawing.image import Image as XLImage

@app.route("/manufacturer/export-units-excel/<product_id>")
def export_units_excel(product_id):

    if not login_required("manufacturer"):
        abort(403)

    units = list(product_units_collection.find({
        "product_id": product_id,
        "manufacturer": session["user"]
    }))

    product = products_collection.find_one({
        "product_id": product_id
    })

    # Convert product created date
    product_created = ""
    if product.get("created_at"):
        product_created = product["created_at"].replace(
            tzinfo=pytz.utc
        ).astimezone(IST).strftime("%d %b %Y %I:%M %p")

    # CREATE WORKBOOK
    wb = Workbook()
    ws = wb.active
    ws.title = "Complete Units"

    headers = [

        "Product ID",
        "Product Name",
        "Manufacturer Name",
        "Brand",
        "Blockchain Tx Hash",
        "Product Created Date",

        "Unit ID",
        "Scratch Code",
        "QR Code",  # IMAGE WILL GO HERE
        "Secure Token",
        "Signature",

        "Status",
        "Owned By",
        "Owned Date",
        "Unit Created Date"

    ]

    ws.append(headers)

    row_num = 2

    for u in units:

        created = ""
        owned = ""

        if u.get("created_at"):
            created = u["created_at"].replace(
                tzinfo=pytz.utc
            ).astimezone(IST).strftime("%d %b %Y %I:%M %p")

        if u.get("last_verified_at"):
            owned = u["last_verified_at"].replace(
                tzinfo=pytz.utc
            ).astimezone(IST).strftime("%d %b %Y %I:%M %p")

        status = "Used" if u.get("owner_username") else "Unused"

        ws.append([

            product.get("product_id"),
            product.get("name"),
            product.get("manufacturer_name"),
            product.get("manufacturer_brand"),
            product.get("tx_hash"),
            product_created,

            u.get("unit_id"),
            u.get("scratch_plain"),
            "",  # QR IMAGE PLACEHOLDER
            u.get("secure_token"),
            u.get("signature"),

            status,
            u.get("owner_username") or "Not claimed",
            owned or "Not owned",
            created

        ])

        # INSERT QR IMAGE
        qr_path = os.path.join("static", u.get("qr_code"))

        if os.path.exists(qr_path):

            img = XLImage(qr_path)

            img.width = 90
            img.height = 90

            cell = f"I{row_num}"  # QR Code column

            ws.add_image(img, cell)

            ws.row_dimensions[row_num].height = 70

        row_num += 1

    output = BytesIO()

    wb.save(output)

    output.seek(0)

    return send_file(

        output,

        as_attachment=True,

        download_name=f"{product_id}_complete_units.xlsx",

        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    )

# ---------- EXPORT PRODUCT UNITS LOGS EXCEL ----------
@app.route("/manufacturer/export-unit-logs-excel/<unit_id>")
def export_unit_logs_excel(unit_id):

    if not login_required("manufacturer"):
        abort(403)

    unit = product_units_collection.find_one({
        "unit_id": unit_id,
        "manufacturer": session["user"]
    })

    if not unit:
        flash("Unit not found", "danger")
        return redirect("/manufacturer/dashboard")

    product = products_collection.find_one({
        "product_id": unit["product_id"]
    })

    logs = list(
        verification_logs_collection.find({
            "unit_id": unit_id
        }).sort("date", -1)
    )

    # Convert dates
    created_date = ""
    owned_date = ""

    if unit.get("created_at"):
        created_date = unit["created_at"].replace(
            tzinfo=pytz.utc
        ).astimezone(IST).strftime("%d %b %Y %I:%M %p")

    if unit.get("last_verified_at"):
        owned_date = unit["last_verified_at"].replace(
            tzinfo=pytz.utc
        ).astimezone(IST).strftime("%d %b %Y %I:%M %p")

    data = []

    for log in logs:

        log_date = ""

        if log.get("date"):
            log_date = log["date"].replace(
                tzinfo=pytz.utc
            ).astimezone(IST).strftime("%d %b %Y %I:%M %p")

        data.append({

            # PRODUCT DETAILS
            "Product Name": product.get("name"),
            "Product ID": product.get("product_id"),
            "Brand": product.get("manufacturer_brand"),
            "Manufacturer": product.get("manufacturer_name"),
            "Blockchain Tx Hash": product.get("tx_hash"),

            # UNIT DETAILS
            "Unit ID": unit.get("unit_id"),
            "Scratch Code": unit.get("scratch_plain"),
            "Secure Token": unit.get("secure_token"),
            "Signature": unit.get("signature"),

            "Status":
                "Used" if unit.get("owner_username")
                else "Unused",

            "Owner":
                unit.get("owner_username") or "Not claimed",

            "Created Date (IST)": created_date,
            "Owned Date (IST)": owned_date or "Not owned",

            # LOG DETAILS
            "Verified By": log.get("username"),
            "Verification Status": log.get("status"),
            "Location": log.get("location"),
            "IP Address": log.get("ip_address"),
            "Verified Date (IST)": log_date

        })

    df = pd.DataFrame(data)

    output = BytesIO()

    df.to_excel(
        output,
        index=False,
        engine="openpyxl"
    )

    output.seek(0)

    response = make_response(output.read())

    response.headers["Content-Disposition"] = \
        f"attachment; filename={unit_id}_full_logs.xlsx"

    response.headers["Content-Type"] = \
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return response

# ---------- VERIFY PAGE ----------
@app.route("/verify")
def verify_product():

    session.pop("scan_unit_id", None)

    return render_template(
        "verify.html",
        stage="scan"
    )


# ---------- VERIFY QR SCAN ----------
@app.route("/s/<signature>")
def scan_signature(signature):

    try:

        if "user" not in session:
            flash("Please login first", "warning")
            return redirect("/login")

        unit = product_units_collection.find_one({
            "signature": signature.strip()
        })

        scanner_ip = request.remote_addr

        lat = request.args.get("lat")
        lon = request.args.get("lon")

        scanner_location = "Unknown"

        if lat and lon:
            scanner_location = get_location_from_gps(lat, lon)


        # ---------- FAKE QR ----------
        if not unit:

            save_verification_log(
                {"product_id": "UNKNOWN"},
                {"unit_id": "UNKNOWN"},
                session["user"],
                "fake",
                scanner_location
            )

            return render_template(
                "verify.html",
                stage="result",
                status="fake",
                scanner_location=scanner_location,
                scanner_ip=scanner_ip
            )


        product = products_collection.find_one({
            "product_id": unit["product_id"]
        })


        session["scan_unit_id"] = unit["unit_id"]


        # CREATED DATE
        created_at_ist = None

        if product.get("created_at"):
            created_at_ist = product["created_at"].replace(
                tzinfo=pytz.utc
            ).astimezone(IST)


        # OWNED DATE
        owned_at_ist = None

        if unit.get("last_verified_at"):
            owned_at_ist = unit["last_verified_at"].replace(
                tzinfo=pytz.utc
            ).astimezone(IST)


        user = users_collection.find_one({
            "username": session["user"]
        })


        role = user.get("role")


        # ---------- MANUFACTURER / ADMIN ----------
        if role in ["manufacturer", "admin"]:

            save_verification_log(
        product,
        unit,
        session["user"],
        "genuine",
        scanner_location
    )
            return render_template(
                "verify.html",
                stage="result",
                status="genuine",

                product=product,
                unit=unit,

                owner=unit.get("owner_username"),
                owner_location=unit.get("owner_location"),
                owner_ip=unit.get("owner_ip_address"),

                scanner_location=scanner_location,
                scanner_ip=scanner_ip,

                created_at_ist=created_at_ist,
                owned_at_ist=owned_at_ist
            )


        # ---------- CUSTOMER ----------
        return render_template(
            "verify.html",
            stage="scratch"
        )


    except Exception as e:

        print("SCAN ERROR:", e)

        return render_template(
            "verify.html",
            stage="result",
            status="fake"
        )



# ---------- VERIFY SCRATCH ----------
@app.route("/verify-scratch", methods=["POST"])
def verify_scratch():

    try:

        if "user" not in session:
            flash("Please login first", "warning")
            return redirect("/login")


        unit_id = session.get("scan_unit_id")

        if not unit_id:
            flash("Invalid session", "danger")
            return redirect("/verify")


        unit = product_units_collection.find_one({
            "unit_id": unit_id
        })


        if not unit:

            return render_template(
                "verify.html",
                stage="result",
                status="fake",
                scanner_location="Unknown",
                scanner_ip=request.remote_addr
            )


        product = products_collection.find_one({
            "product_id": unit["product_id"]
        })


        current_user = session["user"]


        # LOCATION
        lat = request.form.get("lat")
        lon = request.form.get("lon")

        scanner_location = "Unknown"

        if lat and lon:
            scanner_location = get_location_from_gps(lat, lon)


        scanner_ip = request.remote_addr


        now = datetime.utcnow()


        # CREATED DATE
        created_at_ist = None

        if product.get("created_at"):
            created_at_ist = product["created_at"].replace(
                tzinfo=pytz.utc
            ).astimezone(IST)


        # OWNED DATE
        owned_at_ist = None

        if unit.get("last_verified_at"):
            owned_at_ist = unit["last_verified_at"].replace(
                tzinfo=pytz.utc
            ).astimezone(IST)


        scratch_input = request.form["scratch_code"].strip().upper()

        scratch_hash = hashlib.sha256(
            scratch_input.encode()
        ).hexdigest()


        # ---------- FAKE ----------
        if scratch_hash != unit["scratch_hash"]:

            save_verification_log(
                product,
                unit,
                current_user,
                "fake",
                scanner_location
            )

            return render_template(
                "verify.html",
                stage="result",
                status="fake",

                product=product,
                unit=unit,

                owner=unit.get("owner_username"),
                owner_location=unit.get("owner_location"),
                owner_ip=unit.get("owner_ip_address"),

                scanner_location=scanner_location,
                scanner_ip=scanner_ip,

                created_at_ist=created_at_ist,
                owned_at_ist=owned_at_ist
            )


        # ---------- FIRST OWNER ----------
        if not unit.get("is_used"):

            product_units_collection.update_one(

                {"unit_id": unit_id},

                {
                    "$set": {

                        "is_used": True,
                        "owner_username": current_user,
                        "owner_location": scanner_location,
                        "owner_ip_address": scanner_ip,
                        "last_verified_at": now
                    },

                    "$inc": {
                        "verify_count": 1
                    }
                }
            )


            owned_at_ist = now.replace(
                tzinfo=pytz.utc
            ).astimezone(IST)


            updated_unit = product_units_collection.find_one({
                "unit_id": unit_id
            })


            save_verification_log(
                product,
                updated_unit,
                current_user,
                "genuine",
                scanner_location
            )


            return render_template(
                "verify.html",
                stage="result",
                status="genuine",
                first_scan=True,

                product=product,
                unit=updated_unit,

                owner=current_user,
                owner_location=scanner_location,
                owner_ip=scanner_ip,

                scanner_location=scanner_location,
                scanner_ip=scanner_ip,

                created_at_ist=created_at_ist,
                owned_at_ist=owned_at_ist
            )


        # ---------- SAME OWNER ----------
        if unit.get("owner_username") == current_user:

            save_verification_log(
                product,
                unit,
                current_user,
                "already_verified",
                scanner_location
            )


            owned_at_ist = unit["last_verified_at"].replace(
                tzinfo=pytz.utc
            ).astimezone(IST)


            return render_template(
                "verify.html",
                stage="result",
                status="already_verified",

                product=product,
                unit=unit,

                owner=unit.get("owner_username"),
                owner_location=unit.get("owner_location"),
                owner_ip=unit.get("owner_ip_address"),

                scanner_location=scanner_location,
                scanner_ip=scanner_ip,

                created_at_ist=created_at_ist,
                owned_at_ist=owned_at_ist
            )


        # ---------- DUPLICATE ----------
        save_verification_log(
            product,
            unit,
            current_user,
            "duplicate",
            scanner_location
        )


        owned_at_ist = unit["last_verified_at"].replace(
            tzinfo=pytz.utc
        ).astimezone(IST)


        return render_template(
            "verify.html",
            stage="result",
            status="duplicate",

            product=product,
            unit=unit,

            owner=unit.get("owner_username"),
            owner_location=unit.get("owner_location"),
            owner_ip=unit.get("owner_ip_address"),

            scanner_location=scanner_location,
            scanner_ip=scanner_ip,

            created_at_ist=created_at_ist,
            owned_at_ist=owned_at_ist
        )


    except Exception as e:

        print("VERIFY ERROR:", e)

        return render_template(
            "verify.html",
            stage="result",
            status="fake"
        )
    
# ---------- SAVE LOG FUNCTION (UPDATED FULL) ----------
def save_verification_log(product, unit, username, status, location):

    now = datetime.utcnow()

    verification_logs_collection.insert_one({

        "product_id": product.get("product_id"),
        "unit_id": unit.get("unit_id"),

        # SCANNER
        "username": username,
        "status": status,
        "location": location,
        "ip_address": request.remote_addr,

        # OWNER (PERMANENT)
        "owner_username": unit.get("owner_username"),
        "owner_location": unit.get("owner_location"),
        "owner_ip_address": unit.get("owner_ip_address"),

        # MANUFACTURER
        "manufacturer_name": product.get("manufacturer_name"),
        "manufacturer_brand": product.get("manufacturer_brand"),

        # BLOCKCHAIN
        "original_blockchain_tx_hash": product.get("tx_hash"),
        "scanned_tx_hash": product.get("tx_hash"),
        "match_status": "matched",

        "date": now
    })

    product_units_collection.update_one(

        {"unit_id": unit.get("unit_id")},

        {
            "$push": {

                "verification_history": {

                    "username": username,
                    "status": status,
                    "location": location,
                    "ip_address": request.remote_addr,
                    "date": now
                }
            }
        }
    )

# ---------- CUSTOMER DASHBOARD ----------
# ---------- CUSTOMER DASHBOARD ----------
@app.route("/customer/dashboard")
def customer_dashboard():

    if not login_required("customer"):
        abort(403)

    username = session["user"]

    # ================= OWNED PRODUCTS =================
    owned_units_cursor = product_units_collection.find({
        "owner_username": username
    })

    owned_products = []

    for unit in owned_units_cursor:

        product = products_collection.find_one({
            "product_id": unit["product_id"]
        })

        manufactured_at_ist = None
        owned_at_ist = None

        # manufactured date
        if product and product.get("created_at"):
            manufactured_at_ist = product["created_at"].replace(
                tzinfo=pytz.utc
            ).astimezone(IST)

        # owned date
        if unit.get("last_verified_at"):
            owned_at_ist = unit["last_verified_at"].replace(
                tzinfo=pytz.utc
            ).astimezone(IST)

        qr_path = unit.get("qr_code")

        if qr_path:
            qr_path = qr_path.replace("\\", "/")

        owned_products.append({

            "product_id": unit.get("product_id"),
            "unit_id": unit.get("unit_id"),

            "product_name": product.get("name") if product else "-",

            "brand": product.get("manufacturer_brand") if product else "-",

            "manufacturer": product.get("manufacturer_name") if product else "-",

            "scratch_code": unit.get("scratch_plain"),

            "qr_code": qr_path,

            "manufactured_at_ist": manufactured_at_ist,

            "owned_at_ist": owned_at_ist

        })


    # ================= VERIFICATION LOGS =================

    logs_cursor = verification_logs_collection.find({
        "username": username
    }).sort("date", -1)

    logs = []

    for log in logs_cursor:

        ist_date = None

        if log.get("date"):
            ist_date = log["date"].replace(
                tzinfo=pytz.utc
            ).astimezone(IST)

        logs.append({

            "product_id": log.get("product_id"),

            "unit_id": log.get("unit_id"),

            "status": log.get("status"),

            "location": log.get("location"),

            "ip_address": log.get("ip_address"),

            "owner": log.get("owner_username"),

            "manufacturer": log.get("manufacturer_name"),

            "ist_date": ist_date

        })


    return render_template(

        "customer_dashboard.html",

        owned_products=owned_products,

        logs=logs,

        customer_name=session.get("full_name")

    )

# ---------- ADMIN DASHBOARD ----------
@app.route("/admin/dashboard")
def admin_dashboard():

    if not login_required("admin"):
        abort(403)
    session["full_name"] = users_collection.find_one(
        {"username": session["user"]}
    ).get("full_name")

    # ---------- MANUFACTURERS ----------
    manufacturers_cursor = users_collection.find({"role": "manufacturer"})
    manufacturers = []

    for m in manufacturers_cursor:
        credibility = calculate_manufacturer_credibility(
        m["username"]
    )

        users_collection.update_one(
        {"username": m["username"]},
        {"$set": {"credibility_score": credibility}}
    )

        m["credibility_score"] = credibility

        utc = m.get("created_at")

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            m["created_at_ist"] = utc.astimezone(IST)
        else:
            m["created_at_ist"] = None

        manufacturers.append(m)


    # ---------- CUSTOMERS ----------
    customers_cursor = users_collection.find({"role": "customer"})
    customers = []

    for c in customers_cursor:

        utc = c.get("created_at")

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            c["created_at_ist"] = utc.astimezone(IST)
        else:
            c["created_at_ist"] = None

        customers.append(c)


    # ---------- PRODUCTS ----------
    products_cursor = products_collection.find().sort("created_at", -1)
    products = []

    for p in products_cursor:

        utc = p.get("created_at")

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            p["created_at_ist"] = utc.astimezone(IST)
        else:
            p["created_at_ist"] = None

        products.append(p)


    # ---------- LOGS ----------
    logs_cursor = verification_logs_collection.find().sort("date", -1)
    logs = []

    for log in logs_cursor:

        utc = log.get("date")

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            log["ist_date"] = utc.astimezone(IST)
        else:
            log["ist_date"] = None

        logs.append(log)

    return render_template(
        "admin_dashboard.html",
        manufacturers=manufacturers,
        customers=customers,
        products=products,
        logs=logs
    )

@app.route("/admin/manufacturers")
def admin_manufacturers():

    if not login_required("admin"):
        abort(403)

    manufacturers_cursor = users_collection.find({"role":"manufacturer"})

    manufacturers = []

    for m in manufacturers_cursor:

        utc = m.get("created_at")

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            m["created_at_ist"] = utc.astimezone(IST)
        else:
            m["created_at_ist"] = None

        manufacturers.append(m)

    return render_template(
        "admin_manufacturers.html",
        manufacturers=manufacturers
    )

@app.route("/admin/customers")
def admin_customers():

    if not login_required("admin"):
        abort(403)

    customers_cursor = users_collection.find({"role": "customer"})

    customers = []

    for c in customers_cursor:

        utc = c.get("created_at")

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            c["created_at_ist"] = utc.astimezone(IST)
        else:
            c["created_at_ist"] = None

        customers.append(c)

    return render_template(
        "admin_customers.html",
        customers=customers
    )

@app.route("/admin/products")
def admin_products():

    if not login_required("admin"):
        abort(403)

    products_cursor = products_collection.find().sort("created_at", -1)

    products = []

    for p in products_cursor:

        utc = p.get("created_at")

        if utc:
            p["created_at_ist"] = utc.replace(
                tzinfo=pytz.utc
            ).astimezone(IST)
        else:
            p["created_at_ist"] = None

        products.append(p)

    return render_template(
        "admin_products.html",
        products=products
    )

@app.route("/admin/logs")
def admin_logs():

    if not login_required("admin"):
        abort(403)

    logs_cursor = verification_logs_collection.find().sort("date", -1)

    logs = []

    for log in logs_cursor:

        # Convert IST date
        ist_date = None

        if log.get("date"):
            ist_date = log["date"].replace(
                tzinfo=pytz.utc
            ).astimezone(IST)

        # Get unit details
        unit = product_units_collection.find_one({
            "unit_id": log.get("unit_id")
        })

        # Get product details
        product = products_collection.find_one({
            "product_id": log.get("product_id")
        })

        logs.append({

            "product_id": log.get("product_id"),

            "product_name":
                product.get("name") if product else "-",

            "unit_id": log.get("unit_id"),

            "scratch_code":
                unit.get("scratch_plain") if unit else "-",

            "manufacturer":
                log.get("manufacturer_name"),

            "brand":
                log.get("manufacturer_brand"),

            "verified_by":
                log.get("username"),

            "owner":
                log.get("owner_username"),

            "status":
                log.get("status"),

            "location":
                log.get("location"),

            "ip_address":
                log.get("ip_address"),

            "tx_hash":
                log.get("original_blockchain_tx_hash"),

            "ist_date": ist_date

        })

    return render_template(
        "admin_logs.html",
        logs=logs
    )
# ---------- ADMIN VIEW MANUFACTURER PRODUCTS ----------
@app.route("/admin/manufacturer-products/<username>")
def admin_manufacturer_products(username):

    if not login_required("admin"):
        abort(403)

    products_cursor = products_collection.find({
        "manufacturer": username
    }).sort("created_at", -1)

    products = []

    for p in products_cursor:

        utc = p.get("created_at")

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            p["created_at_ist"] = utc.astimezone(IST)
        else:
            p["created_at_ist"] = None

        products.append(p)


    # load other dashboard data normally
    manufacturers = list(users_collection.find({"role":"manufacturer"}))
    customers = list(users_collection.find({"role":"customer"}))
    logs = list(verification_logs_collection.find().sort("date",-1))

    for log in logs:
        utc = log.get("date")
        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            log["ist_date"] = utc.astimezone(IST)

    return render_template(
        "admin_dashboard.html",
        manufacturers=manufacturers,
        customers=customers,
        products=products,  # filtered products only
        logs=logs,
        selected_manufacturer=username
    )

# ---------- ADMIN VIEW PRODUCT LOGS ----------
@app.route("/admin/product-logs/<product_id>")
def admin_product_logs(product_id):

    if not login_required("admin"):
        abort(403)

    product = products_collection.find_one({
        "product_id": product_id
    })

    if not product:
        flash("Product not found", "danger")
        return redirect("/admin/dashboard")


    logs_cursor = verification_logs_collection.find({
        "scanned_product_id": product_id
    }).sort("date", -1)

    logs = []

    for log in logs_cursor:

        utc = log.get("date")

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            log["ist_date"] = utc.astimezone(IST)
        else:
            log["ist_date"] = None

        logs.append(log)


    return render_template(
        "admin_product_logs.html",
        product=product,
        logs=logs
    )

# ---------- ADMIN EXPORT PRODUCTS EXCEL (FULL TABLE DATA) ----------
@app.route("/admin/export-products-excel")
def admin_export_products_excel():

    if not login_required("admin"):
        abort(403)

    products = list(
        products_collection.find()
        .sort("created_at", -1)
    )

    data = []

    for p in products:

        # Convert IST date
        created_ist = ""

        if p.get("created_at"):
            created_ist = (
                p["created_at"]
                .replace(tzinfo=pytz.utc)
                .astimezone(IST)
                .strftime("%d %b %Y %I:%M %p")
            )

        data.append({

            "Product ID": p.get("product_id"),

            "Name": p.get("name"),

            "Brand": p.get("manufacturer_brand"),

            "Manufacturer": p.get("manufacturer_name"),

            "Transaction Hash": p.get("tx_hash"),

            "Quantity": p.get("quantity"),

            "Created Date (IST)": created_ist

        })

    df = pd.DataFrame(data)

    output = BytesIO()

    df.to_excel(
        output,
        index=False,
        engine="openpyxl"
    )

    output.seek(0)

    return send_file(

        output,

        as_attachment=True,

        download_name="admin_products_full_details.xlsx",

        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    )

# ---------- ADMIN EXPORT LOGS ----------
@app.route("/admin/export-logs-excel")
def admin_export_logs_excel():

    if not login_required("admin"):
        abort(403)

    logs_cursor = verification_logs_collection.find().sort("date", -1)

    data = []

    for log in logs_cursor:

        utc = log.get("date")

        ist_date = ""

        if utc:
            ist_date = utc.replace(tzinfo=pytz.utc)\
                .astimezone(IST)\
                .strftime("%d %b %Y %I:%M %p")

        unit = product_units_collection.find_one({
            "unit_id": log.get("unit_id")
        })

        product = products_collection.find_one({
            "product_id": log.get("product_id")
        })

        data.append({

            "Product ID": log.get("product_id"),

            "Product Name": product.get("name") if product else "",

            "Unit ID": log.get("unit_id"),

            "Scratch Code": unit.get("scratch_plain") if unit else "",

            "Manufacturer": log.get("manufacturer_name"),

            "Brand": log.get("manufacturer_brand"),

            "Verified By": log.get("username"),

            "Owner": log.get("owner_username"),

            "Status": log.get("status"),

            "Location": log.get("location"),

            "IP Address": log.get("ip_address"),

            "Blockchain Tx Hash": log.get("original_blockchain_tx_hash"),

            "Date (IST)": ist_date

        })

    df = pd.DataFrame(data)

    output = BytesIO()

    df.to_excel(output, index=False, engine="openpyxl")

    output.seek(0)

    return send_file(

        output,

        as_attachment=True,

        download_name="admin_full_verification_logs.xlsx",

        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    )

# ---------- ADMIN EXPORT MANUFACTURERS EXCEL (FULL DETAILS) ----------
@app.route("/admin/export-manufacturers-excel")
def export_manufacturers_excel():

    if not login_required("admin"):
        abort(403)

    manufacturers = list(
        users_collection.find({"role": "manufacturer"})
    )

    data = []

    for m in manufacturers:

        # Convert date to IST
        created_ist = ""

        if m.get("created_at"):
            created_ist = (
                m["created_at"]
                .replace(tzinfo=pytz.utc)
                .astimezone(IST)
                .strftime("%d %b %Y %I:%M %p")
            )

        # Status
        status = "Active" if m.get("is_active", True) else "Blocked"

        # Approval
        approval = "Approved" if m.get("is_approved", False) else "Pending"

        # Credibility
        credibility = m.get("credibility_score", 100)

        data.append({

            "Username": m.get("username"),

            "Full Name": m.get("full_name"),

            "Email": m.get("email"),

            "Created Date (IST)": created_ist,

            "Status": status,

            "Approval": approval,

            "Credibility Score (%)": credibility

        })

    # Create DataFrame
    df = pd.DataFrame(data)

    # Create Excel in memory
    output = BytesIO()

    df.to_excel(
        output,
        index=False,
        engine="openpyxl"
    )

    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="manufacturers_full_details.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

# ---------- ADMIN EXPORT CUSTOMERS----------
# ---------- ADMIN EXPORT CUSTOMERS EXCEL (FULL DETAILS) ----------
@app.route("/admin/export-customers-excel")
def export_customers_excel():

    if not login_required("admin"):
        abort(403)

    users = list(
        users_collection.find({"role": "customer"})
    )

    data = []

    for u in users:

        # Convert date to IST
        created_ist = ""

        if u.get("created_at"):
            created_ist = (
                u["created_at"]
                .replace(tzinfo=pytz.utc)
                .astimezone(IST)
                .strftime("%d %b %Y %I:%M %p")
            )

        data.append({

            "Username": u.get("username"),

            "Full Name": u.get("full_name"),   # ✅ ADDED

            "Email": u.get("email"),

            "Created Date (IST)": created_ist,

            "Status": "Active" if u.get("is_active") else "Blocked"

        })

    df = pd.DataFrame(data)

    output = BytesIO()

    df.to_excel(
        output,
        index=False,
        engine="openpyxl"
    )

    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="customers_full_details.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

# ---------- ADMIN EXPORT PRODUCT LOGS ----------
@app.route("/admin/export-product-logs-excel/<product_id>")
def admin_export_product_logs_excel(product_id):

    if not login_required("admin"):
        abort(403)
    from io import BytesIO

    logs = list(
        verification_logs_collection.find(
            {"scanned_product_id": product_id}
        )
    )

    data = []

    for log in logs:

        utc = log.get("date")

        ist = ""

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            ist = utc.astimezone(IST)\
                .strftime("%d %b %Y %I:%M %p")

        data.append({

            "Product ID": log.get("scanned_product_id"),

            "Username": log.get("username"),

            "Original Blockchain Hash":
            log.get("original_blockchain_tx_hash"),

            "Scanned Blockchain Hash":
            log.get("scanned_tx_hash"),

            "Status": log.get("status"),

            "Date": ist

        })

    df = pd.DataFrame(data)

    from io import BytesIO

    output = BytesIO()

    df.to_excel(output,index=False)

    output.seek(0)

    response = make_response(output.read())

    response.headers["Content-Disposition"] = \
    f"attachment; filename={product_id}_logs.xlsx"

    response.headers["Content-Type"] = \
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return response

# ---------- ADMIN BLOCK USER ----------
@app.route("/admin/block-user/<username>", methods=["POST"])
def admin_block_user(username):

    if not login_required("admin"):
        abort(403)

    users_collection.update_one(
        {"username": username},
        {"$set": {"is_active": False}}
    )

    flash(f"User '{username}' blocked successfully", "warning")

    user_type = request.args.get("type")

    if user_type == "customer":
        return redirect("/admin/customers")

    return redirect("/admin/manufacturers")

# ---------- ADMIN UNBLOCK USER ----------
@app.route("/admin/unblock-user/<username>", methods=["POST"])
def admin_unblock_user(username):

    if not login_required("admin"):
        abort(403)

    users_collection.update_one(
        {"username": username},
        {"$set": {"is_active": True}}
    )

    flash(f"User '{username}' unblocked successfully", "success")

    user_type = request.args.get("type")

    if user_type == "customer":
        return redirect("/admin/customers")

    return redirect("/admin/manufacturers")

# ---------- ADMIN DELETE USER ----------
@app.route("/admin/delete-user/<username>", methods=["POST"])
def admin_delete_user(username):

    if not login_required("admin"):
        abort(403)

    users_collection.delete_one({"username": username})

    flash(f"User '{username}' deleted successfully", "success")

    user_type = request.args.get("type")

    if user_type == "customer":
        return redirect("/admin/customers")

    return redirect("/admin/manufacturers")

# ---------- ADMIN BLOCK PRODUCT ----------
@app.route("/admin/block-product/<product_id>")
def admin_block_product(product_id):

    if not login_required("admin"):
        abort(403)

    product = products_collection.find_one({"product_id": product_id})

    if not product:
        flash("Product not found", "danger")
        return redirect(url_for("admin_dashboard"))

    products_collection.update_one(
        {"product_id": product_id},
        {"$set": {"is_active": False}}
    )

    flash(f"Product '{product_id}' blocked successfully", "warning")

    return redirect(url_for("admin_dashboard"))


# ---------- ADMIN UNBLOCK PRODUCT ----------
@app.route("/admin/unblock-product/<product_id>")
def admin_unblock_product(product_id):

    if not login_required("admin"):
        abort(403)

    product = products_collection.find_one({"product_id": product_id})

    if not product:
        flash("Product not found", "danger")
        return redirect(url_for("admin_dashboard"))

    products_collection.update_one(
        {"product_id": product_id},
        {"$set": {"is_active": True}}
    )

    flash(f"Product '{product_id}' unblocked successfully", "success")

    return redirect(url_for("admin_dashboard"))


# ---------- ADMIN DELETE PRODUCT ----------
@app.route("/admin/delete-product/<product_id>")
def admin_delete_product(product_id):

    if not login_required("admin"):
        abort(403)

    # Check if owned units exist
    owned_units = product_units_collection.count_documents({
        "product_id": product_id,
        "owner_username": {"$ne": None}
    })

    if owned_units > 0:

        # Soft delete
        products_collection.update_one(
            {"product_id": product_id},
            {
                "$set": {
                    "is_active": False,
                    "deleted_at": datetime.utcnow()
                }
            }
        )

        flash(
            f"Product marked inactive. {owned_units} owned units preserved.",
            "warning"
        )

    else:

        products_collection.delete_one({
            "product_id": product_id
        })

        flash("Product deleted successfully", "success")

    return redirect("/admin/products")

# ---------- ADMIN APPROVE MANUFACTURER ----------
@app.route("/admin/approve-manufacturer/<username>", methods=["POST"])
def approve_manufacturer(username):

    if not login_required("admin"):
        abort(403)

    user = users_collection.find_one({
        "username": username,
        "role": "manufacturer"
    })

    if not user:

        flash("Manufacturer not found", "danger")
        return redirect("/admin/manufacturers")

    # Update approval
    users_collection.update_one(
        {"username": username},
        {"$set": {"is_approved": True}}
    )

    # Send email
    send_approval_email(
        user.get("email"),
        user.get("full_name")
    )

    flash("Manufacturer approved and email sent", "success")

    return redirect("/admin/manufacturers")

# ---------- ADMIN REJECT MANUFACTURER ----------
@app.route("/admin/reject-manufacturer/<username>", methods=["POST"])
def reject_manufacturer(username):

    if not login_required("admin"):
        abort(403)

    result = users_collection.delete_one(
        {
            "username": username,
            "role": "manufacturer"
        }
    )

    if result.deleted_count == 0:
        flash("Manufacturer not found", "danger")
    else:
        flash("Manufacturer rejected and deleted", "info")

    return redirect("/admin/manufacturers")

@app.route("/admin/customer-details/<username>")
def admin_customer_details(username):

    if not login_required("admin"):
        abort(403)

    customer = users_collection.find_one({
        "username": username,
        "role": "customer"
    })

    if not customer:
        flash("Customer not found", "danger")
        return redirect("/admin/customers")

    # ================= OWNED PRODUCTS =================
    units_cursor = product_units_collection.find({
        "owner_username": username
    })

    owned_products = []

    for unit in units_cursor:

        product = products_collection.find_one({
            "product_id": unit["product_id"]
        })

        manufactured_at_ist = None
        owned_at_ist = None

        if product and product.get("created_at"):
            manufactured_at_ist = product["created_at"]\
                .replace(tzinfo=pytz.utc)\
                .astimezone(IST)

        if unit.get("last_verified_at"):
            owned_at_ist = unit["last_verified_at"]\
                .replace(tzinfo=pytz.utc)\
                .astimezone(IST)

        qr_path = unit.get("qr_code")

        if qr_path:
            qr_path = qr_path.replace("\\", "/")

        owned_products.append({

            "product_id": unit.get("product_id"),
            "unit_id": unit.get("unit_id"),

            "product_name": product.get("name") if product else "-",

            "brand": product.get("manufacturer_brand") if product else "-",

            "manufacturer": product.get("manufacturer_name") if product else "-",

            "scratch_code": unit.get("scratch_plain"),

            "qr_code": qr_path,

            "manufactured_at_ist": manufactured_at_ist,

            "owned_at_ist": owned_at_ist

        })


    # ================= VERIFICATION LOGS =================
    logs_cursor = verification_logs_collection.find({
        "username": username
    }).sort("date", -1)

    logs = []

    for log in logs_cursor:

        ist_date = None

        if log.get("date"):
            ist_date = log["date"]\
                .replace(tzinfo=pytz.utc)\
                .astimezone(IST)

        logs.append({

            "product_id": log.get("product_id"),

            "unit_id": log.get("unit_id"),

            "status": log.get("status"),

            "location": log.get("location"),

            "ip_address": log.get("ip_address"),

            "owner": log.get("owner_username"),

            "manufacturer": log.get("manufacturer_name"),

            "ist_date": ist_date

        })


    # USE SAME TEMPLATE AS CUSTOMER DASHBOARD
    return render_template(

        "customer_dashboard.html",

        owned_products=owned_products,

        logs=logs,

        customer_name=customer.get("full_name"),

        admin_view=True
    )

@app.route("/admin/view-manufacturer/<username>")
def admin_view_manufacturer(username):

    if not login_required("admin"):
        abort(403)

    manufacturer = users_collection.find_one({
        "username": username,
        "role": "manufacturer"
    })

    if not manufacturer:
        flash("Manufacturer not found", "danger")
        return redirect("/admin/manufacturers")

    credibility = calculate_manufacturer_credibility(username)

    products_cursor = products_collection.find({
        "added_by": username
    }).sort("created_at", -1)

    products = []

    for p in products_cursor:

        utc = p.get("created_at")

        if utc:
            p["created_at_ist"] = utc.replace(
                tzinfo=pytz.utc
            ).astimezone(IST)

        products.append(p)

    return render_template(
        "manufacturer_dashboard.html",
        products=products,
        manufacturer_credibility=credibility,
        manufacturer_name=manufacturer.get("full_name"),
        viewing_as_admin=True   # ⭐ ADD THIS LINE
    )
# ---------- ERROR HANDLER ----------
@app.errorhandler(403)
def forbidden(e):
    flash("Access denied", "danger")
    return redirect("/")

@app.errorhandler(404)
def not_found(e):
    flash("Page not found", "danger")
    return redirect("/")

# ---------- RUN ----------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=True,
        use_reloader=True
    )