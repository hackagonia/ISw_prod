$env:SECRET_KEY="replace-me"
# optional admin env:
# $env:ADMIN_USERNAME="admin"
# $env:ADMIN_PASSWORD="supersecret"   # or set ADMIN_PASSWORD_HASH

python -m pip install -r requirements.txt
waitress-serve --listen=0.0.0.0:8000 wsgi:application