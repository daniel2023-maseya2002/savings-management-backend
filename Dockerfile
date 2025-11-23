# 1. Base image
FROM python:3.12-slim

# 2. Workdir
WORKDIR /app

# 3. System deps for psycopg2 (Postgres)
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
 && rm -rf /var/lib/apt/lists/*

# 4. Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copy project
COPY . .

# 6. Django config (your project is "savings_api")
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=savings_api.settings

# 7. Start app with Gunicorn using savings_api.wsgi
CMD ["python", "-m", "gunicorn", "savings_api.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
