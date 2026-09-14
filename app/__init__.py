import os

from flask import Flask

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))


def create_app():
    """Application factory — usable by run.py, the lsa CLI, gunicorn, etc."""
    app = Flask(
        __name__,
        static_folder=os.path.join(PACKAGE_DIR, "static"),
        static_url_path="/static",
    )

    from app.routes import main
    app.register_blueprint(main)

    return app
