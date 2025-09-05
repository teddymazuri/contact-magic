from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, Optional, EqualTo

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")

class TwoFactorForm(FlaskForm):
    token = StringField("Authentication Code", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Verify")

class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    phone = StringField("Phone", validators=[Optional()])
    email = StringField("Email", validators=[Optional(), Email()])
    social = StringField("Social Handle/URL", validators=[Optional()])
    submit = SubmitField("Add Contact")

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')