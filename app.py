import os
from datetime import datetime
from flask import (Flask, render_template, redirect, url_for, request, flash,
                   abort)
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, DateField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import (create_engine, Column, Integer, String, Boolean, Date, DateTime)
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv

# Load .env if exists
load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev_secret_change_me")

# Database setup (sqlite)
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///data.db")
engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)
Base = declarative_base()

class User(Base, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(150), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    is_admin = Column(Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Submission(Base):
    __tablename__ = "submissions"
    id = Column(Integer, primary_key=True)
    container_number = Column(String(100), nullable=False)
    melder = Column(String(150), nullable=False)
    datum = Column(Date, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# Flask-Login setup
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    with SessionLocal() as db:
        return db.get(User, int(user_id))

# Forms
class LoginForm(FlaskForm):
    username = StringField("Gebruikersnaam", validators=[DataRequired(), Length(max=150)])
    password = PasswordField("Wachtwoord", validators=[DataRequired()])
    remember = BooleanField("Onthoud mij")
    submit = SubmitField("Inloggen")

class SubmissionForm(FlaskForm):
    container_number = StringField("Containernummer", validators=[DataRequired(), Length(max=100)])
    melder = StringField("Melder", validators=[DataRequired(), Length(max=150)])
    datum = DateField("Datum", validators=[DataRequired()], format='%Y-%m-%d')
    submit = SubmitField("Bewaar gegevens")
    cancel = SubmitField("Cancel")

# Helpers
def get_or_create_default_admin():
    with SessionLocal() as db:
        admin = db.query(User).filter_by(username="admin").first()
        if not admin:
            admin = User(username="admin", is_admin=True)
            admin.set_password("admin123")  # laat gebruiker dit veranderen
            db.add(admin)
            db.commit()
            print("Aanmaken default admin: gebruikersnaam=admin wachtwoord=admin123")
        return admin

# Zorg dat er standaard een admin is bij start (alleen in dev)
get_or_create_default_admin()

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        with SessionLocal() as db:
            user = db.query(User).filter_by(username=form.username.data).first()
            if user and user.check_password(form.password.data):
                login_user(user, remember=form.remember.data)
                flash("Succesvol ingelogd.", "success")
                return redirect(url_for("dashboard"))
            flash("Ongeldige gebruikersnaam of wachtwoord.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Je bent uitgelogd.", "info")
    return redirect(url_for("login"))

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    form = SubmissionForm()
    if form.validate_on_submit():
        if form.cancel.data:
            return redirect(url_for("dashboard"))
        with SessionLocal() as db:
            sub = Submission(
                container_number=form.container_number.data.strip(),
                melder=form.melder.data.strip(),
                datum=form.datum.data,
            )
            db.add(sub)
            db.commit()
            flash("Gegevens bewaard.", "success")
            return redirect(url_for("dashboard"))
    return render_template("dashboard.html", form=form)

@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    with SessionLocal() as db:
        subs = db.query(Submission).order_by(Submission.created_at.desc()).all()
        users = db.query(User).all()
    return render_template("admin.html", submissions=subs, users=users)

# Foutpagina voor forbidden
@app.errorhandler(403)
def forbidden(e):
    return "Toegang geweigerd", 403

if __name__ == "__main__":
    # Voor development: luistert op 0.0.0.0:8000
    app.run(host="0.0.0.0", port=8000, debug=True)