from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_bcrypt import Bcrypt
import sqlite3
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = "thiranex_secret_key_change_this"
bcrypt = Bcrypt(app)

DB_NAME = "users.db"


# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def get_user(username):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user


def create_user(username, password, totp_secret):
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)",
        (username, password_hash, totp_secret)
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Username and password are required.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return redirect(url_for("register"))

        if get_user(username):
            flash("Username already taken.")
            return redirect(url_for("register"))

        totp_secret = pyotp.random_base32()
        create_user(username, password, totp_secret)

        session["pending_user"] = username
        return redirect(url_for("setup_2fa"))

    return render_template("register.html")


@app.route("/setup_2fa")
def setup_2fa():
    username = session.get("pending_user")
    if not username:
        return redirect(url_for("register"))

    user = get_user(username)
    totp_secret = user[3]

    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(name=username, issuer_name="ThiranexSecureLogin")

    qr = qrcode.make(uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    return render_template("setup_2fa.html", qr_code=qr_base64, username=username)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = get_user(username)

        if not user:
            flash("Invalid username or password.")
            return redirect(url_for("login"))

        stored_hash = user[2]

        if not bcrypt.check_password_hash(stored_hash, password):
            flash("Invalid username or password.")
            return redirect(url_for("login"))

        session["pending_2fa_user"] = username
        return redirect(url_for("verify_2fa"))

    return render_template("login.html")


@app.route("/verify_2fa", methods=["GET", "POST"])
def verify_2fa():
    username = session.get("pending_2fa_user")
    if not username:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        user = get_user(username)
        totp_secret = user[3]

        totp = pyotp.TOTP(totp_secret)

        if totp.verify(code):
            session.pop("pending_2fa_user", None)
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid 2FA code. Try again.")
            return redirect(url_for("verify_2fa"))

    return render_template("verify_2fa.html")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
