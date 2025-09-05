📇 Secure Contact Manager (Flask + 2FA)
========================================

A contact management web application built with Flask that helps users securely store and manage their personal or business contacts. The app features user authentication, password hashing, and optional Two-Factor Authentication (2FA) for enhanced security.

✨ Features
------------

1. 🔐 User Authentication – Register, login, and manage accounts with secure password hashing.

2. 🔑 Two-Factor Authentication (2FA) – Optional TOTP-based login for extra protection.

3. 📇 Contact Management – Add, update, delete, and search contacts easily.

4. 📅 Account Metadata – Track when each account was created.

5. 🗄️ Database Powered by SQLAlchemy + SQLite – Simple and reliable data storage.


🚀 Tech Stack
--------------

1. Backend: Flask (Python)

2. Database: SQLite with SQLAlchemy ORM

3. Security: Werkzeug (password hashing), PyOTP (2FA)

4. Frontend: Jinja2 Templates + Bootstrap (for styling)


🎯 Use Cases
-------------

1. A personal address book for managing contacts securely.

2. A starter template for building CRM (Customer Relationship Management) systems.

3. A learning project for Flask authentication, 2FA, and CRUD operations.


------------------------
⚙️ Installation & Setup
------------------------

Follow these steps to set up the project locally:

1️⃣ Clone the Repository
-----------------------
git clone https://github.com/teddymazuri/contact-magic.git

cd contact-magic

2️⃣ Create & Activate a Virtual Environment
------------------------------------------
python3 -m venv venv

source venv/bin/activate   # On Linux/Mac

venv\Scripts\activate      # On Windows

3️⃣ Install Dependencies
-----------------------
pip install -r requirements.txt

4️⃣ Set Up the Database
----------------------
flask db init

flask db migrate -m "Initial migration"

flask db upgrade

5️⃣ Run the Application
----------------------
flask run


By default, the app will be available at 👉 http://127.0.0.1:5000/


🔑 Default Configuration
-------------------------

1. The app uses SQLite by default (stored inside instance/).

2. You can customize configs (like database path or secret key) in config.py or environment variables.

3. For 2FA, the app uses PyOTP (Google Authenticator compatible).
