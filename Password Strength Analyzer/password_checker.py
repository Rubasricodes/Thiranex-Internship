import re
import random
import string
import sqlite3  # Built into Python — no install needed. This is our database.
import bcrypt   # For hashing passwords
from zxcvbn import zxcvbn

COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567890", "iloveyou"
]

# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────

def init_db():
    """
    Creates a local database file called passwords.db
    and sets up a table to store users and their password hashes.
    This runs once when the program starts.
    """
    conn = sqlite3.connect("passwords.db")  # Creates the file if it doesn't exist
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    # IF NOT EXISTS means this won't crash if the table already exists

    conn.commit()  # Save changes
    conn.close()


def get_user_hashes(username):
    """
    Returns all stored password hashes for a given username.
    Used to check if a password was used before.
    """
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()

    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    # The ? is a placeholder — this prevents SQL injection (you'll learn this more in Task 4)

    rows = cursor.fetchall()  # Returns a list of tuples like [('hash1',), ('hash2',)]
    conn.close()

    return [row[0] for row in rows]  # Extract just the hash strings


def save_password(username, password):
    """
    Hashes the password using bcrypt and saves it to the database.
    """
    # bcrypt needs the password as bytes, not a string — so we encode it
    password_bytes = password.encode('utf-8')

    # gensalt() creates a random salt — this makes every hash unique
    # even if two users have the same password
    salt = bcrypt.gensalt()

    # The actual hashing — this is the cryptography part
    hashed = bcrypt.hashpw(password_bytes, salt)

    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, hashed.decode('utf-8'))  # Store hash as a string
    )

    conn.commit()
    conn.close()


def was_password_used_before(username, password):
    """
    Checks if this password matches any previously stored hash for this user.
    bcrypt.checkpw() does the comparison — it never decrypts, just re-hashes and compares.
    """
    password_bytes = password.encode('utf-8')
    stored_hashes = get_user_hashes(username)

    for stored_hash in stored_hashes:
        if bcrypt.checkpw(password_bytes, stored_hash.encode('utf-8')):
            return True  # Match found — password was used before

    return False  # No match — password is new


# ─────────────────────────────────────────────
# PASSWORD STRENGTH LOGIC (same as before)
# ─────────────────────────────────────────────

def check_strength(password):
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Too short — use at least 8 characters (12+ is ideal)")

    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("❌ Add at least one uppercase letter (A-Z)")

    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("❌ Add at least one lowercase letter (a-z)")

    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("❌ Add at least one number (0-9)")

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("❌ Add at least one symbol like !@#$%")

    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback.append("❌ This is one of the most common passwords. Change it entirely.")

    return score, feedback


def get_label(score):
    if score <= 2:
        return "🔴 WEAK"
    elif score <= 4:
        return "🟡 MODERATE"
    else:
        return "🟢 STRONG"


def suggest_stronger(password):
    symbols = "!@#$%^&*"
    suggestion = (
        password
        + random.choice(symbols)
        + random.choice(string.digits)
        + random.choice(string.ascii_uppercase)
        + random.choice(symbols)
    )
    return suggestion


def zxcvbn_analysis(password):
    result = zxcvbn(password)
    score = result['score']
    crack_time = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    suggestions = result['feedback']['suggestions']
    warning = result['feedback']['warning']
    return score, crack_time, suggestions, warning


# ─────────────────────────────────────────────
# MAIN PROGRAM
# ─────────────────────────────────────────────

def main():
    init_db()  # Set up database on startup

    print("=" * 45)
    print("   🔐 Password Strength Analyzer v3")
    print("=" * 45)

    username = input("\nEnter your username: ").strip()
    password = input("Enter a password to check: ").strip()

    # --- Check for reuse first ---
    if was_password_used_before(username, password):
        print("\n⛔ This password was used before for this account. Please choose a new one.")
        return  # Stop here — don't even analyze it

    # --- Rule-based check ---
    score, feedback = check_strength(password)
    label = get_label(score)

    print(f"\n📊 Rule-based Score: {label}  ({score}/6)")

    if feedback:
        print("\nIssues found:")
        for item in feedback:
            print(f"  {item}")
    else:
        print("\n  ✅ Passes all basic rules!")

    # --- zxcvbn smart analysis ---
    z_score, crack_time, suggestions, warning = zxcvbn_analysis(password)
    z_labels = ["🔴 Very Weak", "🔴 Weak", "🟡 Fair", "🟢 Strong", "🟢 Very Strong"]

    print(f"\n🧠 Smart Analysis (zxcvbn): {z_labels[z_score]}  ({z_score}/4)")
    print(f"⏱️  Estimated crack time: {crack_time}")

    if warning:
        print(f"\n⚠️  Warning: {warning}")

    if suggestions:
        print("\n💡 Suggestions:")
        for s in suggestions:
            print(f"  → {s}")

    if z_score < 3:
        suggestion = suggest_stronger(password)
        print(f"\n🔧 Suggested stronger version: {suggestion}")

    # --- Save to DB only if password is strong enough ---
    if z_score >= 3:
        save_password(username, password)
        print(f"\n✅ Password accepted and securely stored for '{username}'.")
        print("   (Stored as a bcrypt hash — not your actual password)")
    else:
        print(f"\n❌ Password not saved — too weak. Strengthen it and try again.")

    print("\n" + "=" * 45)


if __name__ == "__main__":
    main()
