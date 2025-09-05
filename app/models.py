from . import db, login_manager
from flask_login import UserMixin
from datetime import datetime
import pyotp
from werkzeug.security import generate_password_hash, check_password_hash


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    # 2FA Fields
    two_factor_secret = db.Column(db.String(16))  # Base32 secret
    two_factor_enabled = db.Column(db.Boolean, default=False)

    # Created At Field
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def get_totp_uri(self):
        return f"otpauth://totp/ContactMagic:{self.email}?secret={self.two_factor_secret}&issuer=ContactMagic"

    def generate_totp(self):
        return pyotp.TOTP(self.two_factor_secret)

    # 🔑 Password helpers
    def set_password(self, password):
        """Hash and store the password."""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Verify the password."""
        return check_password_hash(self.password, password)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(50))
    email = db.Column(db.String(120))
    social = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
