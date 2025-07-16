# CyberVault — A Secure Personal Data Vault

CyberVault is a secure, Flask-based web application designed to store, encrypt, and manage users' sensitive data with advanced authentication, encryption, and admin monitoring capabilities. Built with modern security practices, it provides secure data storage, OTP-based authentication, and an audit-ready logging system using Splunk.

## Features

### User Functionality
- **Register with OTP Verification** (Email or Google)
- **Login with Password or Google OAuth2**
- **2-Factor Authentication** via Email OTP
- **Encrypt + Store Sensitive Information**
- **Decrypt Own Records Using AES**
- **Update / Delete Own Records**
- **Change Encryption Passphrase**
- **Download Encrypted JSON Backup**
- **Forgot Password Flow with OTP Verification**



### Admin Features 
- **Admin Dashboard** with:
  - Total Users
  - Encrypted Records Count
  - Active Key Versions
- **User Management**
  - Enable / Disable Accounts
  - Assign Roles
- **Suspicious Activity Detection**
  - Failed Login Logs
  - IP Mismatch Tracking
- **Key Rotation Support** (Future data uses new key)
- **View Audit Logs**
- **Admin Panel Access Restricted to Whitelisted IPs**

---

## 🔐 Security Highlights

- **AES Encryption** (CBC mode) for personal data
- **Key Versioning** with Rotation Support
- **Strong Password Policy**
  - Min. 8 characters, Alphanumeric
  - Prevents reuse of last 3 passwords
- **Rate Limiting + IP Logging**
- **OTP Verification via Email**
- **Splunk Integration** for logging:
  - Failed Logins
  - Password Changes
  - Decrypt Events
- **Secure Admin UI** with Role-based Access Control (RBAC)


## ⚙️ Technologies Used

| Tool          | Purpose                          |
|---------------|----------------------------------|
| Python (Flask)| Web Framework (Backend)          |
| MongoDB       | Database for storing user data   |
| HTML/CSS/JS   | Frontend interface               |
| Flask-Mail    | OTP Email Notifications          |
| Google OAuth2 | Gmail Login / Registration       |
| Splunk        | Logging + Security Monitoring    |
| AES (Crypto)  | Data Encryption/Decryption       |
| Marshmallow   | Input Validation                 |
| JWT           | Secure Session Authentication    |
| dotenv        | Config Management                |


## 🧪 Setup Instructions

1. **Clone the Repository**
```bash
git clone https://github.com/your-username/cybervault.git
cd cybervault
````

2. **Create a Virtual Environment**

```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

3. **Install Dependencies**

```bash
pip install -r requirements.txt
```

4. **Setup Environment Variables**
   Create a `.env` file with the following:

```env
FLASK_SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@example.com
EMAIL_PASS=your-email-password
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
SPLUNK_TOKEN=your-splunk-token
SPLUNK_HOST=http://localhost:8088
```

5. **Run the App**

```bash
python app.py
```



## 🧪 Sample Test Users

| Username | Password   | Role   |
| -------- | ---------- | ------ |
| kishore  | Test\@1234 | Viewer |
| admin    | admin123   | Admin  |



## Folder Structure

```
CyberVault/
│
├── app.py                  # Main Flask app
├── encryptor.py            # AES Encryption Logic
├── mailer.py               # OTP Email Service
├── logger.py               # Splunk Logger Integration
├── templates/              # HTML Templates
│   ├── login.html
│   ├── register.html
│   ├── verify_otp.html
│   ├── forgot_password.html
│   └── dashboard.html
├── static/                 # CSS, JS, Particles
├── .env                    # Environment Variables (Not tracked)
├── requirements.txt
└── README.md               # This file
```


## Future Enhancements

* PDF Export of Encrypted Records
* AI-assisted Threat Detection
* WebSocket-based Real-Time Alerts
* Cloud Backup Support


## Maintainer

**Kishore**
Cybersecurity Enthusiast & Developer
`skishorekaarthik@gmail.com`


## License

MIT License — Free to use, modify, and share.
Attribution appreciated 🙌
