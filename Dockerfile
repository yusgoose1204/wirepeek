# Use Python slim image
FROM python:3.10-slim

# Install system packages (tshark)
RUN apt-get update && \
    apt-get install -y tshark curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy all app files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variable Heroku uses for port
ENV PORT=5000

# Expose that port
EXPOSE $PORT

# Run your Flask app
CMD ["python", "wirepeek.py"]

