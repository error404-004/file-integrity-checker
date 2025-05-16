*FILE-INTEGRITY-CHECKER*

*COMPANY* - CODTECH IT SOLUTIONS

*NAME* - DEEPAYAN DEY

*INTERN ID* - CT04DL977

*DOMAIN* -  CYBER SECURITY AND ETHICAL HACKING

*DURATION* - 4 WEEKS

*MENTOR* - NEELA SANTOSH

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Secure File Integrity Monitor
This Python script provides a secure file integrity monitoring solution to detect unauthorized changes to files within a specified directory. It includes both a command-line interface (CLI) and a web interface for monitoring and administration, with a strong focus on security through features like path normalization, password hashing, CSRF protection, and honeypot generation.

Table of Contents

Overview
Features
Installation
Configuration
Usage
Command-Line Interface (CLI)
Web Interface


Honeypots
Email Alerts
Security Considerations


Overview
The Secure File Integrity Monitor script is designed to monitor a specified directory for unauthorized changes to files. It generates a baseline of file hashes, which is signed using HMAC for integrity verification. The script can detect added, removed, or modified files by comparing the current state to the baseline and sends email alerts when changes are detected. Additionally, it includes a web interface for easy administration and monitoring, protected by secure authentication and rate limiting.

Features

Path Normalization: Prevents directory traversal attacks by ensuring all file paths are within the monitored directory.
Admin Password Hashing: Uses bcrypt to securely hash and verify the admin password.
CSRF Protection: Enabled via Flask-WTF to protect the web interface from cross-site request forgery attacks.
Secure Session Cookies: Configured with secure, HTTP-only, and SameSite attributes for enhanced security.
TLS Support: Requires a TLS certificate and key for secure HTTPS access to the web interface.
Rate Limiting: Uses Flask-Limiter to restrict access to sensitive routes, preventing brute-force attacks.
Configurable Honeypots: Generates decoy files within the monitored directory to detect unauthorized access attempts.
File Tampering Detection: Compares current file hashes to a signed baseline to detect changes.
Email Alerts: Sends alerts via SMTP when file changes are detected.
Two-Factor Authentication (OTP): Optional OTP verification for web interface actions.


Installation

Install Dependencies:The script requires several Python modules. Install them using pip:
pip install bcrypt flask flask-wtf wtforms flask-limiter


Set Up TLS Certificate and Key:

Obtain a valid TLS certificate and key for HTTPS. Self-signed certificates can be used for testing but are not recommended for production.
Set the paths to these files in the SSL_CERT_PATH and SSL_KEY_PATH environment variables.


Generate Admin Password Hash:

Use bcrypt to hash the admin password:import bcrypt
password = b"your_password"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print(hashed)


Set the hashed password in the ADMIN_PASSWORD_HASH environment variable.


Set Up HMAC Key:

Generate a secure random key for signing the baseline:python -c "import secrets; print(secrets.token_hex(32))"


Set this key in the INTEGRITY_KEY environment variable.




Configuration
The script is configured via environment variables. Below is a list of required and optional variables:



Variable
Description
Required



ADMIN_PASSWORD_HASH
Bcrypt hash of the admin password.
Yes


SECRET_KEY
Secret key for Flask sessions and CSRF protection.
Yes


MONITORED_DIR
Directory to monitor for file changes (default: /var/monitor).
No


HONEYPOT_DIR
Directory for honeypot files (default: MONITORED_DIR/honeypots).
No


HONEYPOT_COUNT
Number of honeypot files to generate (default: 3).
No


HONEYPOT_SIZE
Size of each honeypot file in bytes (default: 1024).
No


SSL_CERT_PATH
Path to the TLS certificate file.
Yes (web)


SSL_KEY_PATH
Path to the TLS key file.
Yes (web)


BASELINE_PATH
Path to the baseline JSON file (default: baseline.json).
No


SMTP_SERVER
SMTP server for email alerts.
No


SMTP_PORT
SMTP port (default: 587).
No


SMTP_USER
SMTP username.
No


SMTP_PASSWORD
SMTP password.
No


ALERT_EMAIL
Email address to send alerts to.
No


INTEGRITY_KEY
HMAC key for signing the baseline.
Yes


Note: Sensitive information like passwords and keys should be stored securely, such as in a secrets manager or encrypted files.

Usage
Command-Line Interface (CLI)
The CLI provides options to save the baseline, check integrity, scan directories, and run the web interface.

Save Baseline:Generates a baseline of file hashes in the monitored directory and saves it to the baseline file.
python file_integrity.py --save-baseline


Check Integrity:Compares current file hashes to the baseline and alerts if changes are detected.
python file_integrity.py --check


Scan Directory:Scans the specified path and prints the file hashes.
python file_integrity.py --scan --path <path>


Run Web Interface:Starts the Flask web server for the web interface.
python file_integrity.py --web



Web Interface

Access: Navigate to https://<your_server>:443 after starting the web server.
Login: Use the admin password to log in. If configured, enter the OTP for two-factor authentication.
Dashboard: View the integrity status and perform actions like saving the baseline or checking integrity.


Honeypots
The script generates configurable honeypot files within the monitored directory. These decoy files help detect unauthorized access attempts. If a honeypot file is accessed or modified, it can trigger alerts or other security measures.

Configuration: Set HONEYPOT_DIR, HONEYPOT_COUNT, and HONEYPOT_SIZE to customize the honeypot setup.
Detection: Monitor the honeypot files for changes to identify potential security breaches.


Email Alerts
The script can send email alerts when file changes are detected. To enable this feature, configure the following environment variables:

SMTP_SERVER
SMTP_PORT
SMTP_USER
SMTP_PASSWORD
ALERT_EMAIL

Ensure that the SMTP server is properly configured and that the script has the necessary permissions to send emails.

Security Considerations

Environment Variables: Store sensitive information securely, such as in a secrets manager or encrypted files.
TLS Certificate and Key: Use a valid, trusted TLS certificate for secure web access. Self-signed certificates are not recommended for production.
Admin Password: Generate a strong password and store its bcrypt hash securely.
Honeypot Configuration: Adjust the number and size of honeypot files based on your security needs.
Rate Limiting: The web interface includes rate limiting to prevent brute-force attacks on login and OTP routes.
CSRF Protection: Enabled for all web forms to prevent cross-site request forgery attacks.


This README provides a detailed guide to installing, configuring, and using the Secure File Integrity Monitor script. By following these instructions, users can effectively monitor file integrity while maintaining a high level of security.
