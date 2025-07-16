### CyberVault
CyberVault is a secure web application designed for managing sensitive personal information. It prioritizes security through a multi-layered defense architecture, including mandatory multi-factor authentication and application-level encryption.

## ✨ Key Features
Dual Authentication: Sign in using a traditional email/password or with your Google (OAuth 2.0) account.

Mandatory Multi-Factor Authentication (MFA): All login attempts, regardless of the method, require a second-factor One-Time Password (OTP) sent to your registered email.

Application-Level Encryption: Your sensitive data (bank accounts, PAN, notes) is encrypted on the server before it's stored in the database. The platform is designed so that even administrators cannot view plaintext user secrets.

Encryption Key Rotation: Users can rotate their personal encryption keys at any time, re-encrypting all their data with a new key for enhanced security.

Secure Password Policies: Enforces password strength requirements and prevents the reuse of recent passwords.

Admin Dashboard: A special IP-whitelisted dashboard for administrators to view system statistics, manage users, and review audit logs.

Rate Limiting & Lockouts: Protects against brute-force attacks by limiting login attempts.

Data Backup: Users can securely download an unencrypted backup of their data.

## 💻 Technology Stack
Backend: Python, Flask

Database: MongoDB

Authentication: Flask-JWT-Extended, Google OAuth 2.0

Security: Flask-Limiter, custom encryption modules for data protection.

## 🚀 Setup and Installation
Follow these steps to get CyberVault running locally.

### Prerequisites
Python 3.8+

MongoDB

pip and virtualenv

### Installation Steps
Clone the repository:

Bash

git clone https://github.com/your-username/cybervault.git
cd cybervault
Create and activate a virtual environment:

Bash

python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
Install the required dependencies:

Bash

pip install -r requirements.txt
Configure Environment Variables:
Create a .env file in the root directory and add the following variables. Do not use the default hardcoded keys in app.py for production.

Code snippet

FLASK_SECRET_KEY='a-very-strong-and-random-secret-key'
JWT_SECRET_KEY='another-very-strong-and-random-jwt-key'
GOOGLE_CLIENT_ID='your-google-client-id.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET='your-google-client-secret'
MONGO_URI='mongodb://localhost:27017/'
Generate a self-signed SSL certificate for local HTTPS (required for OAuth):

Bash

openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
Run the application:

Bash

python app.py
The application will be available at https://127.0.0.1:5000.

## ⚠️ Security Warning
This codebase is provided as a portfolio project and contains certain configurations intended for development purposes only. Before deploying in a production environment, you MUST:

Remove the Hardcoded Admin Password: In app.py, the following code block creates a major vulnerability and must be removed. You should create your admin user through a secure, separate script.

Python

# REMOVE THIS BLOCK FROM app.py IN PRODUCTION
if username == "admin" and password == "admin123":
    ...
Disable Debug Mode: In app.py, change app.run(debug=True, ...) to app.run(debug=False, ...).

Use Environment Variables: Do not hardcode secret keys, Google credentials, or database URIs directly in the code. Load them from environment variables as shown in the setup steps.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
