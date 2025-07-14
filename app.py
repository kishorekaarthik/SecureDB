from flask import Flask, request, render_template, redirect, url_for, session
from pymongo import MongoClient
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from encryptor import encrypt, decrypt
from auth import validate_password_strength, hash_password, check_password
from logger import log_event
from models import SecretSchema
from bson import ObjectId

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

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form.get("role", "admin")

        valid, msg = validate_password_strength(password)
        if not valid:
            message = msg
        elif users.find_one({"username": username}):
            message = "User already exists"
        else:
            hashed = hash_password(password)
            users.insert_one({
                "username": username,
                "passwords": [hashed],
                "role": role
            })
            return redirect(url_for("login"))
    return render_template("register.html", message=message)

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = users.find_one({"username": username})

        if not user:
            message = "Invalid username"
        elif any(check_password(password, old) for old in user["passwords"]):
            if check_password(password, user["passwords"][0]):
                session["user_id"] = str(user["_id"])
                session["username"] = user["username"]
                session["role"] = user["role"]
                token = create_access_token(identity={"username": username, "role": user["role"]})
                session["token"] = token
                return redirect(url_for("dashboard"))
            else:
                message = "Password recently used or incorrect"
        else:
            message = "Wrong password"
    return render_template("login.html", message=message)

@app.route("/dashboard", methods=["GET", "POST"])
@limiter.limit("5/minute")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    role = session.get("role")
    if role != "admin":
        return "Access Denied", 403

    result = None
    if request.method == "POST":
        data = {
            "bank_account": request.form["bank_account"],
            "upi": request.form["upi"],
            "pan": request.form["pan"],
            "note": request.form["note"]
        }
        errors = SecretSchema().validate(data)
        if errors:
            return f"Validation Error: {errors}", 400

        encrypted_data = {}
        version_data = {}
        for field, value in data.items():
            encrypted_data[field], version_data[field] = encrypt(value)

        secrets.insert_one({
            "user_id": session["user_id"],
            "data": encrypted_data,
            "version": version_data
        })

        log_event(f"Stored encrypted secrets", session["username"])
        result = data

    return render_template("dashboard.html", result=result)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    # Use cert.pem and key.pem for HTTPS support
    app.run(debug=True, ssl_context=("cert.pem", "key.pem"))
