# wsgi.py
from app import app as application  # gunicorn will use "wsgi:application"