# CyberVault: Secure Data Encryption and Audit Logging System

## Overview

CyberVault is a secure Flask-based application that allows users to encrypt sensitive data before storing it in a MongoDB database. It supports secure login with OTP verification, Google OAuth2, AES encryption with key rotation, 2FA, role-based access control (RBAC), audit logging via Splunk, and an admin dashboard.

## Features

### User Features (Viewer Role)

* Register with email and OTP verification
* Login using credentials or Gmail
* Encrypt and store personal data (bank details, etc.)
* Decrypt own data using passphrase + OTP
* Change encryption passphrase
* Download encrypted JSON backup
* Update or delete own data

### Admin Features (Hardcoded user: `admin`, pass: `admin123`)

* View system dashboard (user count, record stats, key versions)
* Monitor suspicious activities (IP mismatch, failed login attempts)
* Key rotation support for future encryption
* View audit logs (timestamped actions with IP)
* Manage users: disable/enable accounts, assign roles
* Admins do **not** see decrypted user data

### Security Enhancements

* AES encryption with key versioning
* OTP-based 2FA for decryption
* JWT authentication
* Strong password enforcement
* HTTPS with self-signed certificates
* Rate limiting
* IP whitelisting for admin access
* Splunk logging for sensitive events
* Secure messaging system (user ↔ admin, encrypted)


## Folder Structure

```
CyberVault/
├── app.py
├── auth.py
├── encryptor.py
├── logger.py
├── otp.py
├── static/
├── templates/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env
└── README.md
```

## Deployment (Docker + ngrok + HTTPS)

### Prerequisites

* Docker
* Ngrok account and authtoken

### 1. Clone and Setup

```bash
git clone https://github.com/your-repo/CyberVault.git
cd CyberVault
cp .env.example .env  # Add Gmail, OAuth, Mongo URI, etc.
```

### 2. Build and Run with Docker

```bash
docker-compose up --build -d
```

### 3. Run ngrok Tunnel

```bash
ngrok http 5000
```

Use the HTTPS URL shown (e.g. `https://abcd1234.ngrok.io`) as your callback URL for Google OAuth.


## Splunk Integration

### Setup Splunk Enterprise

1. Pull and run Splunk container (if not already):

```bash
docker run -d -p 8000:8000 -p 8088:8088 -p 8089:8089 \
  -e SPLUNK_START_ARGS="--accept-license" \
  -e SPLUNK_PASSWORD=admin123 \
  --name splunk splunk/splunk:latest
```

2. Access UI at [http://localhost:8000](http://localhost:8000)

3. Enable HTTP Event Collector (HEC) and create a new token:

   * Name: `securedb`
   * Token: `your_token`
   * Index: `main`

4. Update `logger.py`:

```python
HEC_TOKEN = "your_token"
```

### Fetch Logs via REST API

* Access Splunk logs via the Flask admin dashboard
* View failed login attempts, IP mismatches, actions taken


## Environment Variables

Add the following in your `.env` file:

```
FLASK_SECRET=your_secret
MONGO_URI=mongodb://mongo:27017/securedb
GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret
HEC_TOKEN=your_splunk_token
OTP_EMAIL_SENDER=your_email@gmail.com
OTP_EMAIL_PASSWORD=your_email_app_password
WHITELISTED_ADMIN_IPS=your_whitelisted_ips
```

## Security Notes

* Admin dashboard is IP-restricted via `WHITELISTED_ADMIN_IPS`
* All decryption requires OTP verification
* Admin cannot access actual user data, only encrypted metadata
* Password policy enforced: minimum 8 characters, alphanumeric, not among last 3 used
* HTTPS enabled via self-signed certificate (`cert.pem`, `key.pem`)
* JWT tokens used for protected routes

## License

This project is licensed under the MIT License.

