from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "supersecretkey"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///contacts.db"

    db.init_app(app)
    login_manager.init_app(app)
    migrate = Migrate(app, db)

    from . import routes
    app.register_blueprint(routes.bp)

    return app
