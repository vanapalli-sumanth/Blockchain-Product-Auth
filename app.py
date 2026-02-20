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
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as grequests
from flask import flash
import pandas as pd
from flask import make_response

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

IST = pytz.timezone("Asia/Kolkata")


# ---------- AUTH GUARD ----------
def login_required(role=None):

    if "user" not in session:
        flash("Please login first", "warning")
        return False

    if role and session.get("role") != role:
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

    request_uri = requests.Request(
        "GET",
        authorization_endpoint,
        params={
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "redirect_uri": "http://127.0.0.1:5000/google-auth",
            "scope": "openid email profile",
            "response_type": "code",
        },
    ).prepare().url

    return redirect(request_uri)

# ---------- GOOGLE AUTH CALLBACK ----------
@app.route("/google-auth")
def google_auth():

    code = request.args.get("code")

    google_provider_cfg = requests.get(
        os.getenv("GOOGLE_DISCOVERY_URL")
    ).json()

    token_endpoint = google_provider_cfg["token_endpoint"]

    token_response = requests.post(
        token_endpoint,
        headers={
            "Content-Type": "application/x-www-form-urlencoded"
        },
        data={
            "code": code,
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "redirect_uri": "http://127.0.0.1:5000/google-auth",
            "grant_type": "authorization_code",
        },
    )

    token_json = token_response.json()

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]

    userinfo_response = requests.get(
        userinfo_endpoint,
        headers={
            "Authorization": f"Bearer {token_json['access_token']}"
        },
    )

    userinfo = userinfo_response.json()

    email = userinfo["email"]
    name = userinfo["name"]

    user = users_collection.find_one({"email": email})

    # NEW USER → select role
    if not user:
        session["google_name"] = name
        session["google_email"] = email

        flash("Google account detected. Please select your role.", "info")

        return redirect("/select-role")


    # EXISTING USER → login
    session["user"] = user["username"]
    session["role"] = user["role"]
    flash("Login successful", "success")


    if user["role"] == "manufacturer":
        return redirect("/manufacturer/dashboard")

    return redirect("/customer/dashboard")

@app.route("/select-role", methods=["GET", "POST"])
def select_role():

    if "google_email" not in session:
        flash("Session expired. Please login again.", "warning")
        return redirect("/login")

    if request.method == "POST":

        role = request.form["role"]

        email = session["google_email"]
        name = session["google_name"]

        username = email.split("@")[0]

        users_collection.insert_one({

            "full_name": name,
            "username": username,
            "email": email,
            "password": None,
            "role": role,
            "google_user": True,
            # ⭐ ADD THESE
    "genuine_scans": 0,
    "fake_scans": 0,
    "credibility_score": 100,
            "is_active": True,
            "created_at": datetime.utcnow()

        })

        session["user"] = username
        session["role"] = role

        session.pop("google_email", None)
        session.pop("google_name", None)

        if role == "manufacturer":
            return redirect("/manufacturer/dashboard")

        return redirect("/customer/dashboard")

    return render_template("select_role.html")

# ---------- REGISTER ----------
@app.route("/register", methods=["GET","POST"])
def register():

    if request.method == "POST":

        email = request.form["email"].lower()
        username = request.form["username"]

        # check email exists
        if users_collection.find_one({"email": email}):
            flash("Email already registered", "danger")
            return redirect("/register")

        # check username exists
        if users_collection.find_one({"username": username}):
            flash("Username already taken", "danger")
            return redirect("/register")

        users_collection.insert_one({

            "full_name": request.form["full_name"],
            "username": username,
            "email": email,
            "password": generate_password_hash(request.form["password"]),
            "role": request.form["role"],
            # ⭐ ADD THESE
    "genuine_scans": 0,
    "fake_scans": 0,
    "credibility_score": 100,
            "is_active": True,
            "created_at": datetime.utcnow()

        })

        flash("Account created successfully. Please login.", "success")

        return redirect("/login")

    return render_template("register.html")



# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].lower()
        password = request.form["password"]

        user = users_collection.find_one({
            "email": email
        })

        if not user:
            flash("Email not registered", "danger")
            return redirect("/login")

        if not user["is_active"]:
            flash("Account blocked by admin", "danger")
            return redirect("/login")

        if not check_password_hash(user["password"], password):
            flash("Incorrect password", "danger")
            return redirect("/login")

        # success login
        session["user"] = user["username"]
        session["role"] = user["role"]

        flash("Login successful", "success")

        if user["role"] == "manufacturer":
            return redirect("/manufacturer/dashboard")

        elif user["role"] == "customer":
            return redirect("/customer/dashboard")

        elif user["role"] == "admin":
            return redirect("/admin/dashboard")

    return render_template("login.html")


# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for("login"))



# ---------- MANUFACTURER DASHBOARD ----------
# ---------- MANUFACTURER DASHBOARD ----------
@app.route("/manufacturer/dashboard")
def manufacturer_dashboard():

    if not login_required("manufacturer"):
        abort(403)

    products_cursor = products_collection.find({
        "added_by": session["user"]
    }).sort("created_at", -1)

    products = []

    for p in products_cursor:

        utc_time = p.get("created_at")

        if utc_time:
            utc_time = utc_time.replace(tzinfo=pytz.utc)
            p["created_at_ist"] = utc_time.astimezone(IST)
        else:
            p["created_at_ist"] = None

        products.append(p)

    return render_template(
        "manufacturer_dashboard.html",
        products=products
    )



# ---------- ADD PRODUCT ----------
@app.route("/manufacturer/add-product", methods=["GET", "POST"])
def add_product_route():

    if not login_required("manufacturer"):
        abort(403)

    if request.method == "POST":

        name = request.form["name"]
        product_id = request.form["product_id"]

        # Auto generate product ID
        if not product_id:
            product_id = "PROD-" + uuid.uuid4().hex[:8].upper()

        # Check duplicate
        if products_collection.find_one({"product_id": product_id}):

            flash("Product already exists", "danger")
            return redirect("/manufacturer/add-product")

        # ✅ STEP 1: Generate QR FIRST
        qr = generate_qr()

        secure_token = qr["secure_token"]

        # ✅ STEP 2: Send blockchain transaction
        tx_hash = add_product(
            product_id,
            session["user"],
            secure_token
        )

        if not tx_hash:

            flash("Blockchain transaction failed", "danger")
            return redirect("/manufacturer/add-product")

        # ✅ STEP 3: Save in MongoDB
        products_collection.insert_one({

            "product_id": product_id,
            "name": name,
            "manufacturer": session["user"],
            "added_by": session["user"],
            "tx_hash": tx_hash,
            "secure_token": secure_token,
            "qr_code": qr["qr_path"],
             # ⭐ NEW FIELDS
    "genuine_count": 0,
    "fake_count": 0,
    "credibility_score": 100,
            "is_active": True,
            "created_at": datetime.utcnow()

        })

        flash("Product added successfully on Blockchain", "success")

        return redirect("/manufacturer/dashboard")

    return render_template("add_product.html")



# ---------- MANUFACTURER PRODUCT VERIFICATION LOGS ----------
@app.route("/manufacturer/product-logs/<product_id>")
def manufacturer_product_logs(product_id):

    if not login_required("manufacturer"):
        abort(403)

    product = products_collection.find_one({
        "product_id": product_id,
        "manufacturer": session["user"]
    })

    if not product:
        flash("Product not found", "danger")
        return redirect("/manufacturer/dashboard")

    logs_cursor = verification_logs_collection.find({
        "scanned_product_id": product_id
    }).sort("date", -1)

    logs = []

    for log in logs_cursor:

        utc_time = log["date"].replace(tzinfo=pytz.utc)
        ist_time = utc_time.astimezone(IST)

        log["ist_date"] = ist_time

        logs.append(log)

    return render_template(
        "manufacturer_product_logs.html",
        product=product,
        logs=logs
    )


# ---------- EXPORT ALL MANUFACTURER PRODUCTS TO EXCEL ----------
@app.route("/manufacturer/export-products-excel")
def export_products_excel():

    if not login_required("manufacturer"):
        abort(403)

    products = list(products_collection.find({
        "manufacturer": session["user"]
    }))

    data = []

    for p in products:

        utc_time = p.get("created_at")

        ist_time = ""

        if utc_time:
            utc_time = utc_time.replace(tzinfo=pytz.utc)
            ist_time = utc_time.astimezone(IST).strftime("%d %b %Y %I:%M %p")

        data.append({

            "Product ID": p.get("product_id"),
            "Name": p.get("name"),
            "Manufacturer": p.get("manufacturer"),
            "Blockchain Tx Hash": p.get("tx_hash"),
            "Added Date (IST)": ist_time,
            "Status": "Registered"

        })

    df = pd.DataFrame(data)

    from io import BytesIO
    output = BytesIO()

    df.to_excel(output, index=False, engine="openpyxl")

    output.seek(0)

    response = make_response(output.read())

    response.headers["Content-Disposition"] = \
        "attachment; filename=manufacturer_products.xlsx"

    response.headers["Content-Type"] = \
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return response



# ---------- EXPORT ALL MANUFACTURER PRODUCTS TO PDF ----------
@app.route("/manufacturer/export-products-pdf")
def export_products_pdf():

    if not login_required("manufacturer"):
        abort(403)

    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib import colors
    from io import BytesIO

    products = list(products_collection.find({
        "manufacturer": session["user"]
    }))

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=20,
        rightMargin=20,
        topMargin=20,
        bottomMargin=20
    )

    styles = getSampleStyleSheet()

    # small font style
    small_style = styles["BodyText"]
    small_style.fontSize = 7
    small_style.leading = 9
    small_style.alignment = TA_LEFT

    # table header
    data = [[
        Paragraph("<b>Product ID</b>", small_style),
        Paragraph("<b>Name</b>", small_style),
        Paragraph("<b>Manufacturer</b>", small_style),
        Paragraph("<b>Blockchain Tx Hash</b>", small_style),
        Paragraph("<b>Added Date (IST)</b>", small_style),
        Paragraph("<b>Status</b>", small_style)
    ]]

    # rows
    for p in products:

        utc_time = p.get("created_at")

        ist_time = ""

        if utc_time:
            utc_time = utc_time.replace(tzinfo=pytz.utc)
            ist_time = utc_time.astimezone(IST).strftime("%d %b %Y %I:%M %p")

        data.append([

            Paragraph(str(p.get("product_id")), small_style),

            Paragraph(str(p.get("name")), small_style),

            Paragraph(str(p.get("manufacturer")), small_style),

            Paragraph(str(p.get("tx_hash")), small_style),

            Paragraph(ist_time, small_style),

            Paragraph("Registered", small_style)

        ])

    # column widths compressed to fit page
    table = Table(
        data,
        colWidths=[
            1.0 * inch,  # product id
            1.0 * inch,  # name
            1.1 * inch,  # manufacturer
            2.4 * inch,  # tx hash
            1.3 * inch,  # date
            0.8 * inch   # status
        ]
    )

    # add borders + styling
    table.setStyle(TableStyle([

        ('GRID', (0,0), (-1,-1), 0.5, colors.black),

        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),

        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),

        ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),

        ('FONTSIZE', (0,0), (-1,-1), 7),

        ('VALIGN', (0,0), (-1,-1), 'TOP'),

        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),

    ]))

    doc.build([table])

    buffer.seek(0)

    response = make_response(buffer.read())

    response.headers["Content-Disposition"] = \
        "attachment; filename=manufacturer_products.pdf"

    response.headers["Content-Type"] = "application/pdf"

    return response



# ---------- EXPORT VERIFICATION LOGS TO EXCEL ----------
@app.route("/manufacturer/export-logs-excel/<product_id>")
def export_logs_excel(product_id):

    if not login_required("manufacturer"):
        abort(403)

    logs = list(
        verification_logs_collection.find({
            "scanned_product_id": product_id
        }).sort("date", -1)
    )

    data = []

    for log in logs:

        utc = log.get("date")

        ist_time = ""

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            ist_time = utc.astimezone(IST)\
                .strftime("%d %b %Y %I:%M %p")

        data.append({

            "Product ID": log.get("scanned_product_id"),

            "Username": log.get("username"),

            "Blockchain Product ID": log.get("blockchain_product_id"),

            "Original Blockchain Hash":
            log.get("original_blockchain_tx_hash"),

            "Scanned Blockchain Hash":
            log.get("scanned_tx_hash"),

            "Match Status": log.get("match_status"),

            "Verification Result": log.get("status"),

            "Date (IST)": ist_time

        })


    df = pd.DataFrame(data)

    from io import BytesIO

    output = BytesIO()

    df.to_excel(output, index=False, engine="openpyxl")

    output.seek(0)

    response = make_response(output.read())

    response.headers["Content-Disposition"] = \
        f"attachment; filename={product_id}_verification_logs.xlsx"

    response.headers["Content-Type"] = \
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return response


# ---------- EXPORT VERIFICATION LOGS TO PDF ----------
@app.route("/manufacturer/export-logs-pdf/<product_id>")
def export_logs_pdf(product_id):

    if not login_required("manufacturer"):
        abort(403)

    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib import colors
    from io import BytesIO

    logs = list(verification_logs_collection.find({
        "scanned_product_id": product_id
    }).sort("date", -1))

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=20,
        rightMargin=20,
        topMargin=20,
        bottomMargin=20
    )

    styles = getSampleStyleSheet()

    small_style = styles["BodyText"]
    small_style.fontSize = 7
    small_style.leading = 9
    small_style.alignment = TA_LEFT

    # HEADER
    data = [[
        Paragraph("<b>Customer</b>", small_style),
        Paragraph("<b>Scanned Product ID</b>", small_style),
        Paragraph("<b>Blockchain Product ID</b>", small_style),
        Paragraph("<b>Match Status</b>", small_style),
        Paragraph("<b>Verification Result</b>", small_style),
        Paragraph("<b>Blockchain Tx Hash</b>", small_style),
        Paragraph("<b>Date (IST)</b>", small_style)
    ]]

    # ROWS
    for log in logs:

        utc_time = log.get("date")

        ist_time = ""

        if utc_time:
            utc_time = utc_time.replace(tzinfo=pytz.utc)
            ist_time = utc_time.astimezone(IST).strftime("%d %b %Y %I:%M %p")

        data.append([

            Paragraph(str(log.get("username", "")), small_style),

            Paragraph(str(log.get("scanned_product_id", "")), small_style),

            Paragraph(str(log.get("blockchain_product_id", "")), small_style),

            Paragraph(str(log.get("match_status", "")), small_style),

            Paragraph(str(log.get("status", "")), small_style),

            Paragraph(str(log.get("tx_hash", "")), small_style),

            Paragraph(ist_time, small_style)

        ])

    # COMPRESSED WIDTHS
    table = Table(
        data,
        colWidths=[
            0.9 * inch,
            1.1 * inch,
            1.2 * inch,
            0.9 * inch,
            1.0 * inch,
            2.0 * inch,
            1.2 * inch
        ]
    )

    # PROFESSIONAL STYLING
    table.setStyle(TableStyle([

        ('GRID', (0,0), (-1,-1), 0.5, colors.black),

        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),

        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),

        ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),

        ('FONTSIZE', (0,0), (-1,-1), 7),

        ('VALIGN', (0,0), (-1,-1), 'TOP'),

        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),

    ]))

    doc.build([table])

    buffer.seek(0)

    response = make_response(buffer.read())

    response.headers["Content-Disposition"] = \
        f"attachment; filename={product_id}_verification_logs.pdf"

    response.headers["Content-Type"] = "application/pdf"

    return response

# ---------- VERIFY ----------
# ---------- VERIFY ----------
@app.route("/verify")
def verify_product():

    token = request.args.get("token")

    # =====================================================
    # STEP 1: SHOW SCANNER
    # =====================================================
    if not token:
        return render_template("verify.html", stage="scan")


    # =====================================================
    # STEP 2: VERIFY FROM BLOCKCHAIN
    # =====================================================
    blockchain_product_id, blockchain_manufacturer, is_registered = \
        blockchain_verify_product(token)


    # =====================================================
    # STEP 3: FIND PRODUCT IN DATABASE USING TOKEN
    # =====================================================
    db_product = products_collection.find_one({
        "secure_token": token
    })


    # =====================================================
    # STEP 4: HANDLE FAKE PRODUCT
    # =====================================================
    if not is_registered or not db_product:

        # Try extracting product id if exists
        fake_product_id = token.replace("FAKE_", "")

        # Try matching product by product_id (duplicate QR attempt)
        possible_product = products_collection.find_one({
            "product_id": fake_product_id
        })


        # ================= PRODUCT CREDIBILITY DECREASE =================
        if possible_product:

            products_collection.update_one(
                {"product_id": possible_product["product_id"]},
                {"$inc": {"fake_count": 1}}
            )

            stats = products_collection.find_one({
                "product_id": possible_product["product_id"]
            })

            genuine = stats.get("genuine_count", 0)
            fake = stats.get("fake_count", 0)

            total = genuine + fake

            score = 100 if total == 0 else round((genuine / total) * 100)

            products_collection.update_one(
                {"product_id": possible_product["product_id"]},
                {"$set": {"credibility_score": score}}
            )


        # ================= USER CREDIBILITY DECREASE =================
        if "user" in session:

            users_collection.update_one(
                {"username": session["user"]},
                {"$inc": {"fake_scans": 1}}
            )

            user = users_collection.find_one({
                "username": session["user"]
            })

            genuine = user.get("genuine_scans", 0)
            fake = user.get("fake_scans", 0)

            total = genuine + fake

            score = 100 if total == 0 else round((genuine / total) * 100)

            users_collection.update_one(
                {"username": session["user"]},
                {"$set": {"credibility_score": score}}
            )


        # ================= SAVE LOG =================
        if "user" in session:

            verification_logs_collection.insert_one({

                "scanned_product_id":
                fake_product_id if fake_product_id else "UNKNOWN",

                "username": session["user"],

                "blockchain_product_id": "NOT FOUND",

                "manufacturer": "Unknown",

                "original_blockchain_tx_hash": None,

                "scanned_tx_hash": None,

                "match_status": "mismatched",

                "status": "fake",

                "date": datetime.utcnow()

            })


        return render_template(
            "verify.html",
            stage="result",
            status="fake"
        )


    # =====================================================
    # STEP 5: CHECK IF PRODUCT IS ACTIVE
    # =====================================================
    if db_product.get("is_active", True):

        status = "genuine"
        match_status = "matched"

    else:

        status = "fake"
        match_status = "blocked"


    # =====================================================
    # STEP 6: UPDATE PRODUCT CREDIBILITY
    # =====================================================
    if status == "genuine":

        products_collection.update_one(
            {"secure_token": token},
            {"$inc": {"genuine_count": 1}}
        )

    else:

        products_collection.update_one(
            {"secure_token": token},
            {"$inc": {"fake_count": 1}}
        )


    stats = products_collection.find_one({
        "secure_token": token
    })

    genuine = stats.get("genuine_count", 0)
    fake = stats.get("fake_count", 0)

    total = genuine + fake

    score = 100 if total == 0 else round((genuine / total) * 100)

    products_collection.update_one(
        {"secure_token": token},
        {"$set": {"credibility_score": score}}
    )


    # =====================================================
    # STEP 7: UPDATE USER CREDIBILITY
    # =====================================================
    if "user" in session:

        if status == "genuine":

            users_collection.update_one(
                {"username": session["user"]},
                {"$inc": {"genuine_scans": 1}}
            )

        else:

            users_collection.update_one(
                {"username": session["user"]},
                {"$inc": {"fake_scans": 1}}
            )


        user = users_collection.find_one({
            "username": session["user"]
        })

        genuine = user.get("genuine_scans", 0)
        fake = user.get("fake_scans", 0)

        total = genuine + fake

        score = 100 if total == 0 else round((genuine / total) * 100)

        users_collection.update_one(
            {"username": session["user"]},
            {"$set": {"credibility_score": score}}
        )


    # =====================================================
    # STEP 8: SAVE LOG
    # =====================================================
    if "user" in session:

        verification_logs_collection.insert_one({

            "scanned_product_id": blockchain_product_id,

            "username": session["user"],

            "blockchain_product_id": blockchain_product_id,

            "manufacturer": blockchain_manufacturer,

            "original_blockchain_tx_hash":
                db_product.get("tx_hash"),

            "scanned_tx_hash":
                db_product.get("tx_hash"),

            "match_status": match_status,

            "status": status,

            "date": datetime.utcnow()

        })


    # =====================================================
    # STEP 9: SHOW RESULT
    # =====================================================
    return render_template(
        "verify.html",
        stage="result",
        status=status,
        product=db_product
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


# ---------- CUSTOMER DASHBOARD ----------
@app.route("/customer/dashboard")
def customer_dashboard():

    if not login_required("customer"):
        abort(403)

    logs_cursor = verification_logs_collection.find({
        "username": session["user"]
    }).sort("date", -1)

    logs = []

    for log in logs_cursor:

        # convert UTC → IST
        utc_time = log["date"].replace(tzinfo=pytz.utc)
        ist_time = utc_time.astimezone(IST)

        log["ist_date"] = ist_time

        logs.append(log)

    return render_template(
        "customer_dashboard.html",
        logs=logs
    )


# ---------- ADMIN DASHBOARD ----------
@app.route("/admin/dashboard")
def admin_dashboard():

    if not login_required("admin"):
        abort(403)

    # ---------- MANUFACTURERS ----------
    manufacturers_cursor = users_collection.find({"role": "manufacturer"})
    manufacturers = []

    for m in manufacturers_cursor:

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

@app.route("/admin/export-products-excel")
def admin_export_products_excel():

    if not login_required("admin"):
        abort(403)

    products = list(products_collection.find())

    data = []

    for p in products:

        utc_time = p.get("created_at")

        ist_time = ""

        if utc_time:
            utc_time = utc_time.replace(tzinfo=pytz.utc)
            ist_time = utc_time.astimezone(IST).strftime("%d %b %Y %I:%M %p")

        data.append({

            "Product ID": p.get("product_id"),
            "Name": p.get("name"),
            "Manufacturer": p.get("manufacturer"),
            "Blockchain Tx Hash": p.get("tx_hash"),
            "Added Date (IST)": ist_time,
            "Status": "Active" if p.get("is_active") else "Blocked"

        })

    df = pd.DataFrame(data)

    from io import BytesIO

    output = BytesIO()

    df.to_excel(output, index=False, engine="openpyxl")

    output.seek(0)

    response = make_response(output.read())

    response.headers["Content-Disposition"] = \
        "attachment; filename=admin_products.xlsx"

    response.headers["Content-Type"] = \
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return response


@app.route("/admin/export-logs-excel")
def admin_export_logs_excel():

    if not login_required("admin"):
        abort(403)

    logs = list(
        verification_logs_collection.find()
        .sort("date", -1)
    )

    data = []

    for log in logs:

        utc = log.get("date")

        ist_time = ""

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            ist_time = utc.astimezone(IST)\
                .strftime("%d %b %Y %I:%M %p")

        data.append({

            "Product ID": log.get("scanned_product_id"),

            "Username": log.get("username"),

            "Blockchain Product ID":
            log.get("blockchain_product_id"),

            "Original Blockchain Hash":
            log.get("original_blockchain_tx_hash"),

            "Scanned Blockchain Hash":
            log.get("scanned_tx_hash"),

            "Match Status": log.get("match_status"),

            "Verification Result": log.get("status"),

            "Date (IST)": ist_time

        })


    df = pd.DataFrame(data)

    from io import BytesIO

    output = BytesIO()

    df.to_excel(output, index=False, engine="openpyxl")

    output.seek(0)

    response = make_response(output.read())

    response.headers["Content-Disposition"] = \
        "attachment; filename=admin_logs.xlsx"

    response.headers["Content-Type"] = \
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return response



@app.route("/admin/export-manufacturers-excel")
def export_manufacturers_excel():

    if not login_required("admin"):
        abort(403)

    users = list(users_collection.find({"role":"manufacturer"}))

    data = []

    for u in users:

        utc = u.get("created_at")

        ist = ""

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            ist = utc.astimezone(IST).strftime("%d %b %Y %I:%M %p")

        data.append({

            "Username":u.get("username"),
            "Email":u.get("email"),
            "Created Date":ist,
            "Status":"Active" if u.get("is_active") else "Blocked"

        })

    df = pd.DataFrame(data)

    output = BytesIO()

    df.to_excel(output,index=False,engine="openpyxl")

    output.seek(0)

    response = make_response(output.read())

    response.headers["Content-Disposition"] = \
        "attachment; filename=manufacturers.xlsx"

    response.headers["Content-Type"] = \
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return response

@app.route("/admin/export-manufacturers-pdf")
def export_manufacturers_pdf():

    if not login_required("admin"):
        abort(403)

    from reportlab.platypus import SimpleDocTemplate,Table,TableStyle
    from reportlab.lib import colors

    users = list(users_collection.find({"role":"manufacturer"}))

    buffer = BytesIO()

    doc = SimpleDocTemplate(buffer)

    data=[["Username","Email","Created Date","Status"]]

    for u in users:

        utc=u.get("created_at")

        ist=""

        if utc:
            utc=utc.replace(tzinfo=pytz.utc)
            ist=utc.astimezone(IST).strftime("%d %b %Y %I:%M %p")

        data.append([
            u.get("username"),
            u.get("email"),
            ist,
            "Active" if u.get("is_active") else "Blocked"
        ])

    table=Table(data)

    table.setStyle(TableStyle([
        ('GRID',(0,0),(-1,-1),0.5,colors.black)
    ]))

    doc.build([table])

    buffer.seek(0)

    response=make_response(buffer.read())

    response.headers["Content-Disposition"]="attachment; filename=manufacturers.pdf"

    response.headers["Content-Type"]="application/pdf"

    return response

@app.route("/admin/export-customers-excel")
def export_customers_excel():

    if not login_required("admin"):
        abort(403)

    users=list(users_collection.find({"role":"customer"}))

    data=[]

    for u in users:

        utc=u.get("created_at")

        ist=""

        if utc:
            utc=utc.replace(tzinfo=pytz.utc)
            ist=utc.astimezone(IST).strftime("%d %b %Y %I:%M %p")

        data.append({

            "Username":u.get("username"),
            "Email":u.get("email"),
            "Created Date":ist,
            "Status":"Active" if u.get("is_active") else "Blocked"

        })

    df=pd.DataFrame(data)

    output=BytesIO()

    df.to_excel(output,index=False,engine="openpyxl")

    output.seek(0)

    response=make_response(output.read())

    response.headers["Content-Disposition"]="attachment; filename=customers.xlsx"

    response.headers["Content-Type"]="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return response

@app.route("/admin/export-customers-pdf")
def export_customers_pdf():

    if not login_required("admin"):
        abort(403)

    from reportlab.platypus import SimpleDocTemplate,Table,TableStyle
    from reportlab.lib import colors

    users=list(users_collection.find({"role":"customer"}))

    buffer=BytesIO()

    doc=SimpleDocTemplate(buffer)

    data=[["Username","Email","Created Date","Status"]]

    for u in users:

        utc=u.get("created_at")

        ist=""

        if utc:
            utc=utc.replace(tzinfo=pytz.utc)
            ist=utc.astimezone(IST).strftime("%d %b %Y %I:%M %p")

        data.append([
            u.get("username"),
            u.get("email"),
            ist,
            "Active" if u.get("is_active") else "Blocked"
        ])

    table=Table(data)

    table.setStyle(TableStyle([
        ('GRID',(0,0),(-1,-1),0.5,colors.black)
    ]))

    doc.build([table])

    buffer.seek(0)

    response=make_response(buffer.read())

    response.headers["Content-Disposition"]="attachment; filename=customers.pdf"

    response.headers["Content-Type"]="application/pdf"

    return response


# ---------- BLOCK USER ----------
@app.route("/admin/block-user/<username>")
def admin_block_user(username):

    if not login_required("admin"):
        abort(403)

    user = users_collection.find_one({"username": username})

    if not user:
        flash("User not found", "danger")
        return redirect(url_for("admin_dashboard"))

    users_collection.update_one(
        {"username": username},
        {"$set": {"is_active": False}}
    )

    flash(f"User '{username}' blocked successfully", "warning")

    return redirect(url_for("admin_dashboard"))


# ---------- UNBLOCK USER ----------
@app.route("/admin/unblock-user/<username>")
def admin_unblock_user(username):

    if not login_required("admin"):
        abort(403)

    user = users_collection.find_one({"username": username})

    if not user:
        flash("User not found", "danger")
        return redirect(url_for("admin_dashboard"))

    users_collection.update_one(
        {"username": username},
        {"$set": {"is_active": True}}
    )

    flash(f"User '{username}' unblocked successfully", "success")

    return redirect(url_for("admin_dashboard"))


# ---------- DELETE USER ----------
@app.route("/admin/delete-user/<username>")
def admin_delete_user(username):

    if not login_required("admin"):
        abort(403)

    result = users_collection.delete_one({"username": username})

    if result.deleted_count == 0:
        flash("User not found or already deleted", "danger")
    else:
        flash(f"User '{username}' deleted successfully", "success")

    return redirect(url_for("admin_dashboard"))


# ---------- BLOCK PRODUCT ----------
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


# ---------- UNBLOCK PRODUCT ----------
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


# ---------- DELETE PRODUCT ----------
@app.route("/admin/delete-product/<product_id>")
def admin_delete_product(product_id):

    if not login_required("admin"):
        abort(403)

    result = products_collection.delete_one({"product_id": product_id})

    if result.deleted_count == 0:
        flash("Product not found or already deleted", "danger")
    else:
        flash(f"Product '{product_id}' deleted successfully", "success")

    return redirect(url_for("admin_dashboard"))

@app.errorhandler(403)
def forbidden(e):
    flash("Access denied", "danger")
    return redirect("/")

@app.errorhandler(404)
def not_found(e):
    flash("Page not found", "danger")
    return redirect("/")

@app.errorhandler(500)
def server_error(e):
    flash("Internal server error", "danger")
    return redirect("/")
@app.route("/customer/export-logs-excel")
def customer_export_logs_excel():

    if not login_required("customer"):
        abort(403)

    logs = list(
        verification_logs_collection.find({
            "username": session["user"]
        }).sort("date",-1)
    )

    data = []

    for log in logs:

        utc = log.get("date")

        ist_time = ""

        if utc:
            utc = utc.replace(tzinfo=pytz.utc)
            ist_time = utc.astimezone(IST)\
                .strftime("%d %b %Y %I:%M %p")

        data.append({

            "Product ID": log.get("scanned_product_id"),

            "Blockchain Product ID":
            log.get("blockchain_product_id"),

            "Original Blockchain Hash":
            log.get("original_blockchain_tx_hash"),

            "Scanned Blockchain Hash":
            log.get("scanned_tx_hash"),

            "Status": log.get("status"),

            "Date (IST)": ist_time

        })


    df = pd.DataFrame(data)

    from io import BytesIO

    output = BytesIO()

    df.to_excel(output, index=False, engine="openpyxl")

    output.seek(0)

    response = make_response(output.read())

    response.headers["Content-Disposition"] = \
        "attachment; filename=customer_logs.xlsx"

    response.headers["Content-Type"] = \
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return response

@app.route("/customer/export-logs-pdf")
def customer_export_logs_pdf():

    if not login_required("customer"):
        abort(403)

    from reportlab.platypus import (
        SimpleDocTemplate,
        Table,
        TableStyle,
        Paragraph
    )

    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from io import BytesIO

    logs =list(
    verification_logs_collection.find({
    "username": session["user"]
    }).sort("date",-1)
    )

    buffer = BytesIO()

    doc =SimpleDocTemplate(
    buffer,
    pagesize=letter,
    leftMargin=20,
    rightMargin=20
    )

    styles =getSampleStyleSheet()

    style =styles["BodyText"]

    style.fontSize = 8

    data = [[
    "Product ID",
    "Manufacturer",
    "Tx Hash",
    "Status",
    "Date"
    ]]

    for log in logs:

        utc_time =log.get("date")

        ist_time = ""

        if utc_time:

            utc_time =utc_time.replace(
            tzinfo=pytz.utc)

            ist_time =utc_time.astimezone(IST)\
            .strftime("%d %b %Y %I:%M %p")

        data.append([

        Paragraph(
        str(log.get("scanned_product_id")),
        style),

        Paragraph(
        str(log.get("manufacturer")),
        style),

        Paragraph(
        str(log.get("tx_hash")),
        style),

        Paragraph(
        str(log.get("status")),
        style),

        Paragraph(
        ist_time,
        style)

        ])

    table =Table(
    data,
    colWidths=[
    1.2*inch,
    1.2*inch,
    2.5*inch,
    0.8*inch,
    1.3*inch
    ]
    )

    table.setStyle(TableStyle([
    ('GRID',(0,0),(-1,-1),0.5,colors.black),
    ('BACKGROUND',(0,0),(-1,0),colors.lightgrey)
    ]))

    doc.build([table])

    buffer.seek(0)

    response =make_response(buffer.read())

    response.headers[
    "Content-Disposition"
    ] ="attachment; filename=customer_logs.pdf"

    response.headers[
    "Content-Type"
    ] ="application/pdf"

    return response

@app.route("/admin/export-product-logs-excel/<product_id>")
def admin_export_product_logs_excel(product_id):

    if not login_required("admin"):
        abort(403)

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

@app.route("/admin/export-product-logs-pdf/<product_id>")
def admin_export_product_logs_pdf(product_id):

    if not login_required("admin"):
        abort(403)

    from reportlab.platypus import (
        SimpleDocTemplate,
        Table,
        TableStyle,
        Paragraph
    )

    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.lib import colors

    from io import BytesIO


    logs = list(
        verification_logs_collection.find(
            {"scanned_product_id": product_id}
        ).sort("date", -1)
    )


    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=20,
        rightMargin=20,
        topMargin=20,
        bottomMargin=20
    )


    styles = getSampleStyleSheet()

    style = styles["BodyText"]

    style.fontSize = 8


    # TABLE HEADER
    data = [[

        "Product ID",

        "Username",

        "Original Blockchain Hash",

        "Scanned Blockchain Hash",

        "Status",

        "Date (IST)"

    ]]


    # TABLE ROWS
    for log in logs:

        utc = log.get("date")

        ist = ""

        if utc:

            utc = utc.replace(tzinfo=pytz.utc)

            ist = utc.astimezone(IST)\
                .strftime("%d %b %Y %I:%M %p")


        data.append([

            Paragraph(
                str(log.get("scanned_product_id","")),
                style
            ),

            Paragraph(
                str(log.get("username","")),
                style
            ),

            Paragraph(
                str(log.get("original_blockchain_tx_hash","")),
                style
            ),

            Paragraph(
                str(log.get("scanned_tx_hash","")),
                style
            ),

            Paragraph(
                str(log.get("status","")),
                style
            ),

            Paragraph(
                ist,
                style
            )

        ])


    table = Table(

        data,

        colWidths=[

            1.1*inch,

            1.1*inch,

            2.2*inch,

            2.2*inch,

            0.9*inch,

            1.3*inch

        ]

    )


    table.setStyle(TableStyle([

        ('GRID',(0,0),(-1,-1),0.5,colors.black),

        ('BACKGROUND',(0,0),(-1,0),colors.lightgrey),

        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),

        ('FONTSIZE',(0,0),(-1,-1),8),

        ('VALIGN',(0,0),(-1,-1),'TOP'),

        ('LEFTPADDING',(0,0),(-1,-1),4),

        ('RIGHTPADDING',(0,0),(-1,-1),4),

        ('TOPPADDING',(0,0),(-1,-1),3),

        ('BOTTOMPADDING',(0,0),(-1,-1),3)

    ]))


    doc.build([table])


    buffer.seek(0)

    response = make_response(buffer.read())

    response.headers["Content-Disposition"] = \
    f"attachment; filename={product_id}_verification_logs.pdf"

    response.headers["Content-Type"] = "application/pdf"

    return response

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(debug=True)

