# TrustVault — Secure Document Sharing

TrustVault is a web application built with Flask to support document uploads, controlled sharing, and activity auditing.

## Features

- User registration and login.
- Document upload with file-extension restrictions.
- Private document downloads with server-side access checks.
- Document sharing and permission revocation.
- Audit events for relevant document activities.
- Automated tests for authentication and document access controls.

## Technology Stack

- Python
- Flask
- Flask-Login
- Flask-SQLAlchemy
- SQLite
- pytest

## Prerequisites

- Python 3.10 or later
- Git
- A terminal or PowerShell

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/tanniruanusha18-collab/TrustVault-SecureDocs.git
   cd TrustVault-SecureDocs
   ```

2. Create a virtual environment:

   **Windows PowerShell**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install the dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

## Run the Application

Start the development server:

```bash
python app.py
```

Open the local address shown in your terminal in a browser.

## Run Automated Tests

Run:

```bash
python -m pytest -v
```

The current test suite covers registration, login, rejection of an unsupported file type, denial of unauthorized document downloads, and access revocation.

## Security Documentation

- **[THREATS.md](THREATS.md):** Threat model, mitigations, known limitations, and future security work.
- **[PROMPTS.md](PROMPTS.md):** AI-assisted development and verification log.
- **[test_app.py](test_app.py):** Automated application tests.

## Important Security Limitations

This is a development project and is not yet production-ready.

- The current test suite does not cover every authorization scenario.
- Role-based administrator permissions require further implementation and verification.
- CSRF protection, stronger file validation, and tamper-evident audit logging require further work.
- Use a production-grade server, HTTPS, secure configuration, and protected secrets before deployment.

Do not store real confidential documents or production credentials in this development version.

## Project Goal

The goal of TrustVault is to demonstrate secure document sharing with access control, permission revocation, and accountability through audit logging.