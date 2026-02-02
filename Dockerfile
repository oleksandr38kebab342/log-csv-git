# Use Python 3.9 slim image as base
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install git (required for git operations)
RUN apt-get update && \
    apt-get install -y git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the script
COPY nginx_log_parser.py /app/
COPY requirements.txt /app/

# Install Python dependencies (if any additional packages are needed)
RUN pip install --no-cache-dir -r requirements.txt

# Make script executable
RUN chmod +x /app/nginx_log_parser.py

# Create workspace directory
WORKDIR /workspace

# Set entrypoint
ENTRYPOINT ["python", "/app/nginx_log_parser.py"]

# Default command
CMD ["--help"]