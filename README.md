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

---

## Table of Contents

* Overview
* Features
* Installation
* Configuration
* Usage

  * Command-Line Interface (CLI)
  * Web Interface
* Honeypots
* Email Alerts
* Security Considerations

---

## Overview

The Secure File Integrity Monitor script is designed to monitor a specified directory for unauthorized changes to files. It generates a baseline of file hashes, which is signed using HMAC for integrity verification. The script can detect added, removed, or modified files by comparing the current state to the baseline and sends email alerts when changes are detected. Additionally, it includes a web interface for easy administration and monitoring, protected by secure authentication and rate limiting.

---

## Features

* **Path Normalization**: Prevents directory traversal attacks by ensuring all file paths are within the monitored directory.
* **Admin Password Hashing**: Uses bcrypt to securely hash and verify the admin password.
* **CSRF Protection**: Enabled via Flask-WTF to protect the web interface from cross-site request forgery attacks.
* **Secure Session Cookies**: Configured with secure, HTTP-only, and SameSite attributes for enhanced security.
* **TLS Support**: Requires a TLS certificate and key for secure HTTPS access to the web interface.
* **Rate Limiting**: Uses Flask-Limiter to restrict access to sensitive routes, preventing brute-force attacks.
* **Configurable Honeypots**: Generates decoy files within the monitored directory to detect unauthorized access attempts.
* **File Tampering Detection**: Compares current file hashes to a signed baseline to detect changes.
* **Email Alerts**: Sends alerts via SMTP when file changes are detected.
* **Two-Factor Authentication (OTP)**: Optional OTP verification for web interface actions.

---

## Installation

### 1. Install Dependencies

Install required Python modules:

```bash
pip install bcrypt flask flask-wtf wtforms flask-limiter
```

### 2. Set Up TLS Certificate and Key

Obtain a valid TLS certificate and key for HTTPS. For testing, you can use self-signed certificates. Set the paths in environment variables:

```bash
export SSL_CERT_PATH=/path/to/cert.pem
export SSL_KEY_PATH=/path/to/key.pem
```

### 3. Generate Admin Password Hash

Create a `generate_hash.py` script and run it to generate the hash:

```python
from werkzeug.security import generate_password_hash
print(generate_password_hash("your_password"))
```

Then set it as:

```bash
export ADMIN_PASSWORD_HASH='paste_your_generated_hash_here'
```

### 4. Generate HMAC Key for Integrity

Run:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Set it as:

```bash
export INTEGRITY_KEY='paste_your_generated_key_here'
```

---

## Configuration

The script uses environment variables. Required and optional variables are listed below:

| Variable              | Description                                        | Required  |
| --------------------- | -------------------------------------------------- | --------- |
| ADMIN\_PASSWORD\_HASH | Bcrypt hash of the admin password.                 | Yes       |
| SECRET\_KEY           | Secret key for Flask sessions and CSRF protection. | Yes       |
| MONITORED\_DIR        | Directory to monitor (default: /var/monitor).      | No        |
| HONEYPOT\_DIR         | Directory for honeypot files.                      | No        |
| HONEYPOT\_COUNT       | Number of honeypots (default: 3).                  | No        |
| HONEYPOT\_SIZE        | Size in bytes (default: 1024).                     | No        |
| SSL\_CERT\_PATH       | Path to TLS cert.                                  | Yes (web) |
| SSL\_KEY\_PATH        | Path to TLS key.                                   | Yes (web) |
| BASELINE\_PATH        | Baseline file path (default: baseline.json).       | No        |
| SMTP\_SERVER          | SMTP server.                                       | No        |
| SMTP\_PORT            | SMTP port (default: 587).                          | No        |
| SMTP\_USER            | SMTP username.                                     | No        |
| SMTP\_PASSWORD        | SMTP password.                                     | No        |
| ALERT\_EMAIL          | Email to send alerts to.                           | No        |
| INTEGRITY\_KEY        | HMAC key for baseline signing.                     | Yes       |

> 🔒 Store sensitive values securely.

---

## Usage

### Command-Line Interface (CLI)

Run the script using:

* **Save Baseline**:

```bash
python integrity-checker.py --save-baseline
```

* **Check Integrity**:

```bash
python integrity-checker.py --check
```

* **Scan Directory**:

```bash
python integrity-checker.py --scan --path /your/path
```

* **Run Web Interface**:

```bash
python integrity-checker.py --web
```

---

## Web Interface

1. Launch with the `--web` flag.
2. Visit `https://localhost` or your domain.
3. Log in with the admin password.
4. If OTP is enabled, enter it after logging in.
5. Use the dashboard to save or check baseline integrity.

---

## Honeypots

Set honeypot config through environment variables. The tool creates fake decoy files to detect unauthorized access.

* Configure:

```bash
export HONEYPOT_COUNT=3
export HONEYPOT_SIZE=1024
```

* Detection: Changes in honeypots trigger alerts.

---

## Email Alerts

Set up the following to receive alerts via email:

```bash
export SMTP_SERVER='smtp.example.com'
export SMTP_PORT=587
export SMTP_USER='your_email@example.com'
export SMTP_PASSWORD='your_password'
export ALERT_EMAIL='alert_receiver@example.com'
```

Ensure internet access and correct credentials.

---

## Security Considerations

* Store secrets in `.env` or secrets manager
* Use strong passwords
* Use HTTPS (TLS) only
* Apply rate limiting for login
* Use CSRF protection

---

By following this guide, you can deploy and maintain a secure file integrity monitoring system suitable for various environments.
