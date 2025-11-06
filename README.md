# savings-management-backend
Savings Management System – Backend (Django + DRF)

🛠️ Backend — CreditJambo API

Django REST Framework + JWT + Device Security + Email OTP

📌 Overview

The CreditJambo backend provides secure banking API services:

User authentication & JWT (access + refresh)

Device-based security & admin approval

OTP email verification & password reset

Savings wallet (deposit, withdraw, balance)

Transactions tracking & analytics

Notifications system (admin → users)

Beautiful HTML email templates (EN + Kinyarwanda)

🚀 Tech Stack
Technology	Purpose
Django + Django REST Framework	API backend
PostgreSQL	Database
JWT Authentication	Secure session tokens
Celery + Redis*(optional)*	Async email delivery
Django Templates	Branded email HTML
SMTP Email	OTP + notifications
📂 Project Structure
backend/
 ┣ core/              # Settings, URLs, project config
 ┣ auth/              # Login, Register, OTP, JWT
 ┣ savings/           # Wallet: deposit, withdraw, transactions
 ┣ devices/           # Device approval system
 ┣ notifications/     # System alerts / admin notifications
 ┣ templates/
 ┃ ┗ emails/          # Email HTML templates
 ┣ manage.py
 ┗ requirements.txt

⚙️ Installation & Setup
1️⃣ Create Virtual Environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

2️⃣ Install Requirements
pip install -r requirements.txt

3️⃣ Configure .env

Create .env file:

SECRET_KEY=your-secret
DEBUG=True
DATABASE_URL=postgres://user:pass@localhost:5432/creditjambo
EMAIL_HOST_USER=you@gmail.com
EMAIL_HOST_PASSWORD=app-password
FRONTEND_URL=http://localhost:5173

4️⃣ Apply Migrations + Start Server
python manage.py migrate
python manage.py runserver

5️⃣ Create Admin
python manage.py createsuperuser

🔐 Auth Flow
Endpoint	Action
POST /auth/register/	Register
POST /auth/login/	Login + Device info
POST /auth/token/refresh/	Refresh JWT
POST /auth/otp/request/	Request OTP
POST /auth/otp/verify/	Confirm OTP
💳 Savings Module
Endpoint	Action
POST /savings/deposit/	Deposit funds
POST /savings/withdraw/	Withdraw funds
GET /savings/transactions/	Transaction history
✉️ Beautiful Email Templates

✅ OTP Code email

✅ Deposit receipt

✅ Withdrawal notification

✅ Low balance alert

All bilingual: English + Kinyarwanda

🛡️ Security

JWT access + refresh

Device fingerprinting

Admin approval for devices

OTP authentication

Strong password hashing

📧 Email Preview Example

templates/emails/base_email.html + components

📜 License

MIT — feel free to use, improve & contribute.