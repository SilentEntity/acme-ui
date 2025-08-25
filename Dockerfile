# Use official Python image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    libpq-dev \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install acme.sh
RUN curl https://get.acme.sh | sh

# Add acme.sh to PATH
ENV PATH="/root/.acme.sh/:${PATH}"

# Copy requirements file and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copy project files
COPY . .

# Collect static files (if you have static files)
RUN python manage.py collectstatic --noinput

# Expose port 8000
EXPOSE 8000

# Run Django development server (replace with gunicorn for production)
CMD ["gunicorn", "sslmanager.wsgi:application", "--bind", "0.0.0.0:8000"]
