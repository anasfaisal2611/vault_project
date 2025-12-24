# Time-Bound Digital Access Vault

## Project Overview
A full-stack web application that allows users to securely store sensitive text
and share it via temporary, rule-based access links.

## Tech Stack
- Backend: Flask (Python)
- Frontend: HTML, CSS, JavaScript
- Database: SQLite
- Authentication: JWT

## Features
- User registration & login
- Secure vault items
- Share links with expiry, view limits, and password
- Backend-enforced access rules
- Immutable audit logs

## How to Run
1. Install Python 3.10+
2. pip install -r requirements.txt
3. python app.py
4. Open frontend/login.html

## Security Notes
- Backend is the single source of truth
- Passwords are hashed using bcrypt
- Share links are random and unguessable
- Access is invalidated permanently after rule violation
