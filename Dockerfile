# Use Python 3.12 slim image for a smaller footprint
FROM python:3.12-slim

# Set environment variables
# PYTHONDONTWRITEBYTECODE: Prevents Python from writing pyc files to disc
# PYTHONUNBUFFERED: Prevents Python from buffering stdout and stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/app \
    USER_NAME=yacertmanager \
    USER_ID=1000

# Install system dependencies
# openssl: Required for certificate operations
# curl: Useful for healthchecks (optional but recommended)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN groupadd -g $USER_ID $USER_NAME \
    && useradd -m -u $USER_ID -g $USER_NAME -s /bin/bash $USER_NAME

# Set working directory
WORKDIR $APP_HOME

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directories for data and logs with correct permissions
RUN mkdir -p ca-data logs \
    && chown -R $USER_NAME:$USER_NAME $APP_HOME

# Switch to non-root user
USER $USER_NAME

# Expose the port the app runs on
EXPOSE 8000

# Define volumes for persistent data
VOLUME ["$APP_HOME/ca-data", "$APP_HOME/logs"]

# Healthcheck to ensure the application is running
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Command to run the application
# Using uvicorn directly
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
