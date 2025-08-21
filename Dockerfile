# Use slim Python base
FROM python:3.12-slim

# Install exiftool (system package) and minimal OS deps
RUN apt-get update && apt-get install -y --no-install-recommends \
      exiftool \
  && rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /app

# Copy and install Python deps first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Port comes from Render's $PORT
ENV PORT=8000

# Gunicorn WSGI entrypoint
CMD ["gunicorn", "wsgi:application", "-b", "0.0.0.0:8000", "--workers", "2", "--threads", "2", "--timeout", "60"]
