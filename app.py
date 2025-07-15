from flask import Flask, request, render_template, redirect, url_for, session, send_file
from pymongo import MongoClient
from flask_jwt_extended import JWTManager, create_access_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from bson.objectid import ObjectId
from functools import wraps
from datetime import datetime, timezone
import json
import io
import os
import pathlib
import random
import requests

from encryptor import encrypt, decrypt
from auth import validate_password_strength, hash_password, check_password
from logger import log_event, fetch_splunk_logs
from models import SecretSchema
from email_utils import send_otp_email
from keyvault import rotate_user_key

from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
from pip._vendor import cachecontrol

app = Flask(__name__)
app.secret_key = "super-secret-key"
app.config["JWT_SECRET_KEY"] = "jwt-super-secret"

jwt = JWTManager(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client.securedb
users = db.users
secrets = db.secrets
# Google OAuth Setup
GOOGLE_CLIENT_ID = "36181066792-e8o4i6t9s6i5g0lktc6pof3c9o164ji8.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# 🔹 Gmail Registration Flow
register_flow = Flow.from_client_secrets_file(
    "client_secret.json",
    scopes=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_uri="https://127.0.0.1:5000/gmail-register/callback"
)

# 🔹 Gmail Login Flow
login_flow = Flow.from_client_secrets_file(
    "client_secret.json",
    scopes=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_uri="https://127.0.0.1:5000/gmail-login/callback"
)

# Admin IP whitelist
ALLOWED_ADMIN_IPS = ["127.0.0.1", "::1"]

def ip_whitelist_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        user_ip = request.remote_addr
        if user_ip not in ALLOWED_ADMIN_IPS:
            log_event(f"Blocked admin access from IP: {user_ip}", "system")
            return "Access denied: unauthorized IP", 403
        return view_func(*args, **kwargs)
    return wrapped_view

@app.route("/")
def home():
    return render_template("landing.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        if username == "admin":
            return "Cannot register admin user", 403

        valid, msg = validate_password_strength(password)
        if not valid:
            message = msg
        elif users.find_one({"username": username}):
            message = "User already exists"
        else:
            otp = str(random.randint(100000, 999999))
            session["temp_user"] = {
                "username": username,
                "email": email,
                "password": hash_password(password),
                "otp": otp
            }
            send_otp_email(email, otp)
            return redirect(url_for("verify_email_otp"))

    return render_template("register.html", message=message)

@app.route("/gmail-register")
def gmail_register():
    auth_url, _ = register_flow.authorization_url(prompt="consent")
    return redirect(auth_url)
@app.route("/gmail-register/callback")
def gmail_register_callback():
    register_flow.fetch_token(authorization_response=request.url)

    credentials = register_flow.credentials
    session_req = requests.Session()
    cached = cachecontrol.CacheControl(session_req)
    token_req = google.auth.transport.requests.Request(session=cached)
    id_info = google.oauth2.id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_req,
        audience=GOOGLE_CLIENT_ID
    )

    email = id_info.get("email")
    name = id_info.get("name")

    existing = users.find_one({"email": email})
    if existing:
        return redirect(url_for("login"))  # User already registered

    # First-time Gmail registration
    otp = str(random.randint(100000, 999999))
    session["temp_user"] = {
        "username": name,
        "email": email,
        "password": None,  # No password for Gmail login
        "otp": otp,
        "from_gmail": True
    }
    send_otp_email(email, otp)
    return redirect(url_for("verify_email_otp"))


@app.route("/verify-email-otp", methods=["GET", "POST"])
def verify_email_otp():
    if "temp_user" not in session and "pending_gmail_user" not in session:
        return redirect(url_for("register"))

    data = session.get("temp_user") or session.get("pending_gmail_user")

    if request.method == "POST":
        input_otp = request.form["otp"]
        if input_otp == data["otp"]:
            new_user = {
                "username": data["username"],
                "email": data["email"],
                "role": "viewer",
                "created": datetime.now(),
                "active": True
            }
            if data.get("password"):  # 👈 Only add if password is present
                new_user["passwords"] = [data["password"]]
            users.insert_one(new_user)

            session.pop("temp_user", None)
            session.pop("pending_gmail_user", None)
            log_event(f"Email OTP verified & registered: {data['username']}")
            return redirect(url_for("login"))

        return "Invalid OTP", 403

    return '''
    <h3>Verify OTP</h3>
    <form method="post">
        <input type="text" name="otp" required>
        <button type="submit">Verify OTP</button>
    </form>
    '''

@app.route("/callback")
def callback():
    GOOGLE_FLOW.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        return "State mismatch", 400

    credentials = GOOGLE_FLOW.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = google.oauth2.id_token.verify_oauth2_token(
        credentials.id_token, token_request, GOOGLE_CLIENT_ID
    )

    email = id_info.get("email")
    user = users.find_one({"email": email})

    if not user:
        session["temp_google_user"] = {"email": email}
        return redirect(url_for("register_with_gmail"))

    session["user_id"] = str(user["_id"])
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["token"] = create_access_token(identity={"username": user['username']})
    session["otp_verified"] = True
    log_event(f"Gmail login successful: {user['username']}")
    return redirect(url_for("dashboard"))



@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    ip = request.remote_addr

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # ✅ Hardcoded admin login
        if username == "admin" and password == "admin123":
            session["username"] = "admin"
            session["role"] = "admin"
            session["token"] = create_access_token(identity={"username": "admin"})
            log_event("SUCCESSFUL LOGIN — admin (IP: {})".format(ip), "admin")
            return redirect(url_for("admin_dashboard"))

        # 🔒 Normal viewer login
        user = users.find_one({"username": username})
        if not user:
            log_event(f"FAILED LOGIN — Unknown username: {username} (IP: {ip})", "system")
            message = "Invalid username"
        elif not user.get("active", True):
            log_event(f"FAILED LOGIN — Disabled user: {username} (IP: {ip})", username)
            message = "User account disabled"
        elif "passwords" not in user:
            message = "This account uses Gmail login. Please sign in using Google."
        else:
            if any(check_password(password, old) for old in user["passwords"]):
                if check_password(password, user["passwords"][0]):
                    session["user_id"] = str(user["_id"])
                    session["username"] = user["username"]
                    session["role"] = user["role"]
                    session["token"] = create_access_token(identity={"username": username})
                    session.pop("otp_verified", None)
                    log_event(f"SUCCESSFUL LOGIN — {username} (IP: {ip})", username)
                    return redirect(url_for("request_otp"))
                else:
                    log_event(f"FAILED LOGIN — Reused old password: {username} (IP: {ip})", username)
                    message = "Password recently used or incorrect"
            else:
                log_event(f"FAILED LOGIN — Wrong password: {username} (IP: {ip})", username)
                message = "Wrong password"

    return render_template("login.html", message=message)

@app.route("/gmail-login")
def gmail_login():
    auth_url, state = login_flow.authorization_url(
        prompt="consent",
        access_type="offline",
        include_granted_scopes="true"
    )
    session["state"] = state  # Save state to verify later
    return redirect(auth_url)


@app.route("/gmail-login/callback")
def gmail_login_callback():
    login_flow.fetch_token(authorization_response=request.url)

    if session.get("state") != request.args.get("state"):
        return "State mismatch", 400

    credentials = login_flow.credentials
    session_req = requests.Session()
    cached = cachecontrol.CacheControl(session_req)
    token_req = google.auth.transport.requests.Request(session=cached)

    try:
        idinfo = id_token.verify_oauth2_token(
            credentials._id_token, token_req, GOOGLE_CLIENT_ID
        )
    except ValueError:
        return "Token verification failed", 400

    email = idinfo.get("email")
    user = users.find_one({"email": email})

    if not user:
        # Gmail user not registered yet → go to Gmail registration
        session["temp_google_user"] = {"email": email, "name": idinfo.get("name")}
        return redirect(url_for("gmail_register"))

    # User exists → continue with OTP
    session["user_id"] = str(user["_id"])
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["token"] = create_access_token(identity={"username": user["username"]})

    otp = str(random.randint(100000, 999999))
    session["otp"] = otp
    session.pop("otp_verified", None)

    try:
        send_otp_email(user["email"], otp)
        log_event(f"Gmail login OTP sent to {user['username']}")
    except Exception as e:
        print("Failed to send OTP email:", e)

    return redirect(url_for("request_otp"))


@app.route("/request-otp")
def request_otp():
    if "user_id" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    otp = session.get("otp")

    if not otp:
        # Fallback: regenerate OTP if it doesn't exist in session
        otp = str(random.randint(100000, 999999))
        session["otp"] = otp

        user = users.find_one({"username": username})
        if user and "email" in user:
            try:
                send_otp_email(user["email"], otp)
                log_event(f"Re-sent OTP to {username} (via fallback)", username)
            except Exception as e:
                print(f"[ERROR] Failed to send OTP email to {username}: {e}")
        else:
            print(f"[WARN] No email found for user: {username}")

    return '''
    <p>OTP has been sent to your registered email. Proceed to <a href="/verify-otp">Verify OTP</a>.</p>
    '''


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        user_otp = request.form["otp"]
        if user_otp == session.get("otp"):
            session["otp_verified"] = True
            return redirect(url_for("dashboard"))
        return "Invalid OTP", 403

    return '''
    <h3>Enter OTP</h3>
    <form method="post">
        <input type="text" name="otp" required>
        <button type="submit">Verify</button>
    </form>
    '''
@app.route("/dashboard", methods=["GET", "POST"])
@limiter.limit("10/minute")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    role = session.get("role")
    if role == "viewer" and not session.get("otp_verified"):
        return redirect(url_for("request_otp"))

    user_id = session["user_id"]
    form_data = {}
    edit_id = request.args.get("edit")

    if request.method == "POST":
        fields = ["bank_account", "upi", "pan", "note"]
        try:
            data = {k: request.form[k] for k in fields}
        except KeyError:
            return "Missing form fields", 400

        errors = SecretSchema().validate(data)
        if errors:
            return f"Validation Error: {errors}", 400

        encrypted = {}
        versions = {}
        for k, v in data.items():
            encrypted[k], versions[k] = encrypt(v)

        if request.form.get("edit_id"):
            sid = request.form["edit_id"]
            result = secrets.update_one(
                {"_id": ObjectId(sid), "user_id": user_id},
                {"$set": {"data": encrypted, "version": versions}}
            )
            if result.modified_count:
                log_event(f"Updated record {sid} on dashboard", session["username"])
        else:
            secrets.insert_one({
                "user_id": user_id,
                "data": encrypted,
                "version": versions,
                "created_at": datetime.now(timezone.utc)
            })
            log_event("Inserted new personal data", session["username"])

        return redirect(url_for("dashboard"))

    # GET request handling
    records = []
    for doc in secrets.find({"user_id": user_id}).sort("created_at", -1):
        decrypted = {
            field: decrypt(doc["data"][field], doc["version"][field])
            for field in ["bank_account", "upi", "pan", "note"]
        }
        decrypted["_id"] = str(doc["_id"])
        records.append(decrypted)

    # If user is editing an existing record
    if edit_id:
        try:
            doc = secrets.find_one({"_id": ObjectId(edit_id), "user_id": user_id})
        except Exception:
            return "Invalid record ID", 400

        if doc:
            form_data = {
                field: decrypt(doc["data"][field], doc["version"][field])
                for field in ["bank_account", "upi", "pan", "note"]
            }
        else:
            return "Unauthorized access or record not found", 403

    return render_template("dashboard.html", records=records, form_data=form_data, edit_id=edit_id)

    records = []
    for doc in secrets.find({"user_id": user_id}).sort("created_at", -1):
        decrypted = {
            field: decrypt(doc["data"][field], doc["version"][field])
            for field in ["bank_account", "upi", "pan", "note"]
        }
        decrypted["_id"] = str(doc["_id"])
        records.append(decrypted)

    if edit_id:
        doc = secrets.find_one({"_id": ObjectId(edit_id), "user_id": user_id})
        if doc:
            form_data = {
                field: decrypt(doc["data"][field], doc["version"][field])
                for field in ["bank_account", "upi", "pan", "note"]
            }

    return render_template("dashboard.html", records=records, form_data=form_data, edit_id=edit_id)

@app.route("/change_passphrase", methods=["POST"])
def change_passphrase():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    all_records = list(secrets.find({"user_id": user_id}))

    new_version = rotate_user_key(user_id)

    for record in all_records:
        new_data = {}
        new_versions = {}

        for field in record["data"]:
            decrypted = decrypt(record["data"][field], record["version"][field])
            new_data[field], new_versions[field] = encrypt(decrypted, new_version)


        secrets.update_one(
            {"_id": record["_id"]},
            {"$set": {"data": new_data, "version": new_versions}}
        )

    log_event("Rotated encryption key", session["username"])
    return redirect(url_for("dashboard"))

@app.route("/backup")
def download_backup():
    if "user_id" not in session:
        return redirect(url_for("login"))

    data = list(secrets.find({"user_id": session["user_id"]}))
    for d in data:
        d["_id"] = str(d["_id"])
        d["user_id"] = str(d["user_id"])
        if "created_at" in d:
            d["created_at"] = d["created_at"].isoformat()  

    backup = json.dumps(data, indent=2)
    return send_file(
        io.BytesIO(backup.encode()),
        mimetype='application/json',
        as_attachment=True,
        download_name="securedb_backup.json"
    )

@app.route("/delete/<record_id>")
def delete_record(record_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    secrets.delete_one({"_id": ObjectId(record_id), "user_id": session["user_id"]})
    log_event("Deleted personal data", session["username"])
    return redirect(url_for("dashboard"))

@app.route("/admin")
@ip_whitelist_required
def admin_dashboard():
    if session.get("role") != "admin":
        return "Access Denied", 403

    # Collect statistics
    total_users = users.count_documents({})
    total_viewers = users.count_documents({"role": "viewer"})
    total_admins = users.count_documents({"role": "admin"})
    total_records = secrets.count_documents({})

    # Read encryption key versions
    with open("keyvault.json", "r") as f:
        keys = json.load(f)
        total_keys = len(keys)

    # List of users
    user_list = list(users.find({}, {"username": 1, "role": 1, "active": 1}))
    for u in user_list:
        u["_id"] = str(u["_id"])

    # ✅ Get logs from Splunk instead of access.log
    try:
        logs = fetch_splunk_logs()
    except Exception as e:
        logs = [f"Could not fetch Splunk logs: {e}"]

    # View all encrypted records (admin can't decrypt)
    encrypted_records = []
    for doc in secrets.find().sort("created_at", -1):
        user = users.find_one({"_id": ObjectId(doc["user_id"])})
        username = user["username"] if user else "Unknown"
        encrypted_records.append({
            "username": username,
            "data": doc["data"],
            "created": doc.get("created_at", "Unknown")
        })

    return render_template("admin_dashboard.html",
        total_users=total_users,
        total_viewers=total_viewers,
        total_admins=total_admins,
        total_records=total_records,
        total_keys=total_keys,
        user_list=user_list,
        logs=logs,
        encrypted_records=encrypted_records
    )

@app.route("/admin/toggle/<uid>", methods=["POST"])
@ip_whitelist_required
def toggle_user(uid):
    if session.get("role") != "admin":
        return "Access Denied", 403

    user = users.find_one({"_id": ObjectId(uid)})
    users.update_one({"_id": ObjectId(uid)}, {"$set": {"active": not user["active"]}})
    log_event(f"{'Disabled' if user['active'] else 'Enabled'} user {user['username']}", session["username"])
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/role/<uid>", methods=["POST"])
@ip_whitelist_required
def change_role(uid):
    if session.get("role") != "admin":
        return "Access Denied", 403

    new_role = request.form["new_role"]
    users.update_one({"_id": ObjectId(uid)}, {"$set": {"role": new_role}})
    log_event(f"Changed role of user {uid} to {new_role}", session["username"])
    return redirect(url_for("admin_dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))  # Redirect to landing page


if __name__ == "__main__":
    app.run(debug=True, ssl_context=("cert.pem", "key.pem"))
