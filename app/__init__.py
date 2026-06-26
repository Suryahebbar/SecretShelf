# ============================================================
# SecretShelf | app/__init__.py
# Purpose: Flask application factory
# ============================================================

from flask import Flask
from .db import init_pool, close_pool
import os
from dotenv import load_dotenv

load_dotenv()

def create_app():
    app = Flask(
        __name__,
        template_folder='../templates'
    )

    app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config['ENCRYPTION_KEY'] = os.getenv('ENCRYPTION_KEY')

    # Initialize database connection pool
    with app.app_context():
        init_pool()

    # Register blueprints
    from .auth import auth_bp
    from .secrets import secrets_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(secrets_bp)

    # Close pool on shutdown
    import atexit
    atexit.register(close_pool)

    return app
