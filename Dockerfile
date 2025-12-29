# ---- Builder Stage ----
# This stage builds the Python environment with all dependencies.
FROM python:3.12-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies into a virtual environment
RUN python -m venv .venv \
    && . .venv/bin/activate \
    && pip install -r requirements.txt

# ---- Final Stage ----
# This stage creates the final, lean production image.
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/app \
    PATH="/app/.venv/bin:$PATH"

# Install only necessary runtime system dependencies
# openssl: Required for certificate operations
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and group for security
RUN addgroup --system --gid 1000 homelabpki \
    && adduser --system --uid 1000 --ingroup homelabpki homelabpki

# Set working directory
WORKDIR $APP_HOME

# Copy the virtual environment from the builder stage
COPY --from=builder /app/.venv .venv

# Copy the application code
COPY . .

# Create and set permissions for data and log directories
RUN mkdir -p ca-data logs \
    && chown -R homelabpki:homelabpki $APP_HOME

# Switch to the non-root user
USER homelabpki

# Expose the port the app runs on
EXPOSE 8000

# Define volumes for persistent data
VOLUME ["/app/ca-data", "/app/logs"]

# Healthcheck to ensure the application is running
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD [ "python", "-c", "import http.client; conn = http.client.HTTPConnection('localhost', 8000); conn.request('GET', '/health'); exit(0) if conn.getresponse().status == 200 else exit(1)" ]

# Command to run the application using the virtual environment's uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
