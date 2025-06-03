# Simple Register Login

A simple user registration and login system built with Flask.  
It includes email verification using Mailjet, password hashing with bcrypt, and token-based session management via cookies.

## 🌟 Features

- 📧 Email + password registration
- 🛡️ Email verification via Mailjet
- 🔐 Passwords hashed with bcrypt
- 🧠 SQLite database for storage
- 🍪 Cookie-based token sessions
- 🚫 No frontend (for now), backend only

## 🔧 Requirements

- Python 3.9+
- Flask
- flask-cors
- python-dotenv
- bcrypt
- mailjet_rest

Install all with:

```bash
pip install -r requirements.txt
```
## ⚠️ Disclaimer

This project is intended **for educational and demonstration purposes only**.

It does not include full production-level security measures, such as:
- Input sanitization
- CSRF protection
- Rate limiting
- Email confirmation double-checks
- Token expiration and revocation
- Logging and monitoring
- Error handling best practices

**Please do not use this code in a production environment** without implementing proper security, validation, and testing.

Use at your own risk. I warned you.

my portfolio
https://koupi-dev.github.io/
