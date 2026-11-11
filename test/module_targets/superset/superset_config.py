"""Disposable lab settings; preserve the release default unless explicitly rotated."""
import os

# Keep the module's documented metadata location and real Flask/CSRF behavior.
SQLALCHEMY_DATABASE_URI = 'sqlite:////app/superset_home/superset.db'
if os.environ.get('MODULE_TARGET_ROTATED_SECRET'):
    SECRET_KEY = os.environ['MODULE_TARGET_ROTATED_SECRET']
