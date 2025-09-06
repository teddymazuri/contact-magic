from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from . import db
from .models import User, Contact
from .forms import LoginForm, ContactForm, RegistrationForm
from datetime import datetime, timedelta
from sqlalchemy import func


import csv
import base64
import io, pyotp, qrcode
from flask import Response, send_file
import pandas as pd

bp = Blueprint("main", __name__)

@bp.route("/")
def home():
    return render_template("home.html")

@bp.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if not current_user.two_factor_secret:
        # Generate new secret if not already set
        secret = pyotp.random_base32()
        current_user.two_factor_secret = secret
        db.session.commit()

    # Create QR Code
    uri = current_user.get_totp_uri()
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    if request.method == "POST":
        code = request.form.get("code")
        totp = current_user.generate_totp()
        if totp.verify(code):
            current_user.two_factor_enabled = True
            db.session.commit()
            flash("Two-factor authentication enabled successfully!", "success")
            return redirect(url_for("main.dashboard"))
        else:
            flash("Invalid code. Please try again.", "danger")

    return render_template("setup_2fa.html", qr_code=qr_b64, secret=current_user.two_factor_secret)

@bp.route("/disable-2fa")
@login_required
def disable_2fa():
    current_user.two_factor_enabled = False
    current_user.two_factor_secret = None
    db.session.commit()
    flash("Two-factor authentication disabled.", "warning")
    return redirect(url_for("main.settings"))


@bp.route("/settings")
@login_required
def settings():
    import pyotp
    import qrcode
    import io
    import base64

    user = current_user

    qr_code_base64 = None
    if user.two_factor_enabled and user.two_factor_secret:
        # Generate QR code again
        totp = pyotp.TOTP(user.two_factor_secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.email,
            issuer_name="Contact Magic"
        )
        qr = qrcode.make(provisioning_uri)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        qr_code_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template("settings.html", user=user, qr_code_base64=qr_code_base64)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = User(email=form.email.data)
        new_user.set_password(form.password.data)  
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            if user.two_factor_enabled:
                # Store user ID temporarily in session until 2FA verified
                session["pre_2fa_user_id"] = user.id
                return redirect(url_for("main.two_factor"))

            # Normal login if 2FA not enabled
            login_user(user, remember=form.remember.data)
            return redirect(url_for("main.dashboard"))

        flash("Invalid email or password", "danger")
    return render_template("login.html", form=form)

@bp.route("/two-factor", methods=["GET", "POST"])
def two_factor():
    from .forms import TwoFactorForm
    import pyotp

    if "pre_2fa_user_id" not in session:
        return redirect(url_for("main.login"))

    form = TwoFactorForm()
    user = User.query.get(session["pre_2fa_user_id"])

    if form.validate_on_submit():
        totp = pyotp.TOTP(user.two_factor_secret)
        if totp.verify(form.token.data, valid_window=1):  # Allow slight time drift
            session.pop("pre_2fa_user_id", None)
            login_user(user)
            flash("Two-factor authentication successful!", "success")
            return redirect(url_for("main.dashboard"))
        else:
            flash("Invalid or expired code, please try again.", "danger")

    return render_template("two_factor.html", form=form)


@bp.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    form = ContactForm()

    # Handle new contact submission
    if form.validate_on_submit():
        new_contact = Contact(
            name=form.name.data,
            phone=form.phone.data,
            email=form.email.data,
            social=form.social.data,
            user_id=current_user.id,
            created_at=datetime.utcnow()  
        )
        db.session.add(new_contact)
        db.session.commit()
        flash("Contact added successfully!", "success")
        return redirect(url_for("main.dashboard"))

    # Handle search
    search_query = request.args.get("search", "").strip()
    query = Contact.query.filter_by(user_id=current_user.id)
    if search_query:
        query = query.filter(
            (Contact.name.ilike(f"%{search_query}%")) |
            (Contact.phone.ilike(f"%{search_query}%")) |
            (Contact.email.ilike(f"%{search_query}%"))
        )

    # Pagination
    page = request.args.get("page", 1, type=int)
    contacts = query.paginate(page=page, per_page=5)

    # Stats
    total_contacts = Contact.query.filter_by(user_id=current_user.id).count()
    month_contacts = Contact.query.filter(Contact.user_id == current_user.id,
                                          func.strftime("%Y-%m", Contact.created_at) == datetime.utcnow().strftime("%Y-%m")).count()
    email_contacts = Contact.query.filter(Contact.user_id == current_user.id, Contact.email.isnot(None), Contact.email != "").count()
    social_contacts = Contact.query.filter(Contact.user_id == current_user.id,Contact.social.isnot(None), Contact.social != "").count()

    latest_contact = Contact.query.filter_by(user_id=current_user.id).order_by(Contact.created_at.desc()).first()

    stats = {
        "total_contacts": total_contacts,
        "month_contacts": month_contacts,
        "email_contacts": email_contacts,
        "social_contacts": social_contacts,
        "latest_contact": latest_contact
    }

    return render_template(
        "dashboard.html",
        stats=stats,
        contacts=contacts,
        form=form,
        search_query=search_query
    )

@bp.route("/contact/<int:id>/edit", methods=["GET", "POST"])
@login_required
def edit_contact(id):
    contact = Contact.query.get_or_404(id)
    if contact.user_id != current_user.id:
        flash("You are not authorized to edit this contact.", "danger")
        return redirect(url_for("main.dashboard"))

    form = ContactForm(obj=contact)
    if form.validate_on_submit():
        contact.name = form.name.data
        contact.phone = form.phone.data
        contact.email = form.email.data
        contact.social = form.social.data
        db.session.commit()
        flash("Contact updated successfully!", "success")
        return redirect(url_for("main.dashboard"))

    return render_template("edit_contact.html", form=form)

@bp.route("/contact/<int:id>/delete", methods=["POST"])
@login_required
def delete_contact(id):
    contact = Contact.query.get_or_404(id)
    if contact.user_id != current_user.id:
        flash("You are not authorized to delete this contact.", "danger")
        return redirect(url_for("main.dashboard"))

    db.session.delete(contact)
    db.session.commit()
    flash("Contact deleted successfully!", "success")
    return redirect(url_for("main.dashboard"))

@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.login"))

# Utility route to create a test user
@bp.route("/create-user")
def create_user():
    if not User.query.filter_by(email="admin@example.com").first():
        hashed_pw = generate_password_hash("Password123", method="sha256")
        user = User(email="admin@example.com", password=hashed_pw)
        db.session.add(user)
        db.session.commit()
    return "User created: admin@example.com / Password123"

@bp.route("/dashboard/download_csv")
@login_required
def download_csv():
    contacts = Contact.query.filter_by(user_id=current_user.id).all()

    # Use StringIO for CSV output
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(["Name", "Phone", "Email", "Social", "Created At"])
    for c in contacts:
        writer.writerow([c.name, c.phone, c.email, c.social, c.created_at])

    output = si.getvalue()
    si.close()

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=contacts.csv"}
    )


@bp.route("/dashboard/download_excel")
@login_required
def download_excel():
    contacts = Contact.query.filter_by(user_id=current_user.id).all()

    # Convert to DataFrame
    df = pd.DataFrame([{
        "Name": c.name,
        "Phone": c.phone,
        "Email": c.email,
        "Social": c.social,
        "Created At": c.created_at
    } for c in contacts])

    # Save Excel to memory
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Contacts")
    output.seek(0)

    return send_file(
        output,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name="contacts.xlsx"
    )

@bp.route('/import_contacts', methods=['POST'])
@login_required
def import_contacts():
    file = request.files.get('file')
    if not file:
        flash('No file selected!', 'danger')
        return redirect(url_for('main.dashboard'))

    try:
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif file.filename.endswith('.xlsx'):
            df = pd.read_excel(file)
        else:
            flash('Unsupported file format. Please upload CSV or XLSX.', 'danger')
            return redirect(url_for('main.dashboard'))

        # Normalize column names
        df.columns = [c.strip().capitalize() for c in df.columns]

        required_cols = {'Name', 'Phone', 'Email', 'Social'}
        if not required_cols.issubset(df.columns):
            flash(f'Missing required columns: {required_cols - set(df.columns)}', 'danger')
            return redirect(url_for('main.dashboard'))

        for _, row in df.iterrows():
            created_at = None
            if 'Created at' in df.columns and not pd.isna(row.get('Created at')):
                try:
                    created_at = pd.to_datetime(row['Created at'])
                except Exception:
                    created_at = datetime.utcnow()
            else:
                created_at = datetime.utcnow()

            contact = Contact(
                name=row.get('Name'),
                phone=row.get('Phone'),
                email=row.get('Email'),
                social=row.get('Social'),
                created_at=created_at,
                user_id=current_user.id
            )
            db.session.add(contact)

        db.session.commit()
        flash('Contacts imported successfully!', 'success')

    except Exception as e:
        flash(f'Error importing file: {str(e)}', 'danger')

    return redirect(url_for('main.dashboard'))
