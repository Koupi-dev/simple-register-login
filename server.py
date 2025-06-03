from flask import Flask, request, jsonify, make_response
from mailjet_rest import Client
from flask_cors import CORS
import secrets
import bcrypt
import sqlite3
import re
import os
from dotenv import load_dotenv
import random

# Load environment variables from .env
load_dotenv()

api_mailjet = os.getenv("MAILJET_API_KEY")
secretkey_mailjet = os.getenv("MAILJET_SECRET_KEY")
sender_mailaddress = os.getenv("EMAIL_SENDER")
mailjet = Client(auth=(api_mailjet, secretkey_mailjet), version='v3.1')

DB_PATH = "accounts.db"

# Function Definitions
def init_db(): # Create tables if they don't exist
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            username TEXT,
            displayname TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS verify_codes (
            email TEXT PRIMARY KEY,
            code TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_tokens (
            email TEXT PRIMARY KEY,
            token TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Generate a secure random token
def generate_token():
    token_lengh = 32
    return secrets.token_hex(token_lengh) 

def store_verification_code(email, code):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO verify_codes (email, code)
    VALUES (?, ?)
    """, (email, str(code)))
    conn.commit()
    conn.close()


def save_account(email, password, username, displayname):
# # Securely hash the user's password using bcrypt
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    # Open a connection to the SQLite database
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        

        # Save email, hashed password, username and display name into the database
        cursor.execute("""
        INSERT INTO users (email, password, username, displayname)
        VALUES (?, ?, ?, ?)
        """, (email, hashed, username, displayname))
        conn.commit()
        return True

    except sqlite3.Error as e:
        print(f"DataBase Error: {e}")
        return False

    finally:
        conn.close()

# Check if the email address is already registered
def is_email_registered(email):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    conn.close()
    return 1 if result else 0

# Check if the username is already registered
def is_username_registered(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return 1 if result else 0

# Send a verification email using Mailjet
def send_verification_email(to_email, code):
    data = {
        'Messages': [
            {
                "From": {
                    "Email": sender_mailaddress,
                    "Name": "YourAppName"
                },
                "To": [
                    {
                        "Email": to_email,
                        "Name": "YourAppName"
                    }
                ],
                "Subject": "【YourAppName】Verification code",
                "TextPart": f"Please enter the following confirmation code：\n\n{code}"
            }
        ]
    }
    result = mailjet.send.create(data=data)
    if result.status_code == 200:
        print("✅ メール送信成功！")
        return 1
    else:
        print("❌ エラー:", result.status_code, result.json())
        return 0


app = Flask(__name__)
CORS(app, supports_credentials=True)

# Register route
@app.route("/register", methods=["POST"])
def register_route():
    data = request.json
    displayname = data.get("displayname", "")
    username = data.get("username", "")
    mailaddress = data.get("mailaddress", "")
    password = data.get("password", "")

    # Perform input validation for registration form
    errors = []
    if len(password) < 8:
        errors.append("・Password must be at least 8 characters")
    if len(password) > 15:
        errors.append("・Password must be 15 characters or less")
    if not displayname.strip():
        errors.append("・Display name not entered")
    if len(displayname) > 15:
        errors.append("・Display name must be less than 15 characters")
    if not username.strip():
        errors.append("・Username not entered")
    if len(username) > 16:
        errors.append("・Username must be 16 characters or less")
    if not mailaddress.strip():
        errors.append("・No email address has been entered.")
    if not re.fullmatch(r"[a-zA-Z0-9]+", username):
        errors.append("・Username contains characters that cannot be used（available: a-z A-Z 0-9）")
    if is_username_registered(username):
        errors.append("・This username is already in use")
    if is_email_registered(mailaddress):
        errors.append("・That email address is already in use")

    if errors:
        return jsonify({
            "success": False,
            "errors": errors
        }), 400

    # Generate a 5-digit verification code (10000–99999)
    verifycode = random.randint(10000, 99999)
    # Print("verify code:", verifycode) # for testing only
    result = send_verification_email(mailaddress, verifycode)  #send email and check result (1/0)
    # Result = 1 # for testing only
    if result == 1: # If success return "success": true and 400
      store_verification_code(mailaddress, verifycode)
      return jsonify({"success": True, "next": "verify"}), 200
    else: # If fail return "success": False and 400
        return jsonify({"success": False, "why": "invalidEmail"}), 400

# Verify route
@app.route("/verify", methods=["POST"])
def verify_code():
    data = request.json
    email = data.get("email", "").strip().lower()
    code = data.get("code", "")
    password = data.get("password", "")
    username = data.get("username", "")
    displayname = data.get("displayname", "")

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT code FROM verify_codes WHERE email = ?", (email,))
        row = cursor.fetchone()

        if row and str(row[0]) == str(code):
            save_account(email, password, username, displayname)
            # If success delete verify code of verified
            cursor.execute("DELETE FROM verify_codes WHERE email = ?", (email,))
            conn.commit()
            return jsonify({"success": True, "message": "Verification Success"}), 200
        else:
            return jsonify({"success": False, "reason": "Invalid Code"}), 400

    except Exception as e:
        return jsonify({"success": False, "reason": f"DBError"}), 500

    finally:
        conn.close()




# Login route
@app.route("/login", methods=["POST"])
def login_route():
    data = request.json
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    try: # Try to select email but if not exist return - Email address or password is incorrect.
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password, username, displayname FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode(), user[0]):
            token = generate_token()
            cursor.execute("INSERT OR REPLACE INTO user_tokens (email, token) VALUES (?, ?)", (email, token))
            conn.commit()

            response = make_response(jsonify({
                "success": True,
                "username": user[1],
                "displayname": user[2]
            }))
            response.set_cookie(
                "token",
                token,
                httponly=True,
                secure=True,
                samesite="Lax"
            )
            return response
        else:
            return jsonify({
                "success": False,
                "message": "Email address or password is incorrect."
            }), 401

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Server Error"
        }), 500
    finally:
        conn.close()

# Token verify route
@app.route("/me", methods=["POST"])
def get_profile():
    token = request.cookies.get("token", "")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Retrieve username and display name using the token
    cursor.execute("""
        SELECT users.username, users.displayname
        FROM users
        JOIN user_tokens ON users.email = user_tokens.email
        WHERE user_tokens.token = ?
    """, (token,))
    user = cursor.fetchone()
    conn.close()

    if user: # If success return username and displayname
        return jsonify({
            "success": True,
            "username": user[0],
            "displayname": user[1]
        })
    else:  # If token is invalid, return an error
        return jsonify({
            "success": False,
            "message": "Invalid Token"
        }), 401

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)

