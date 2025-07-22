# Use the official Python image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Install dependencies and system tools
COPY requirements.txt .
RUN apt-get update && \
    apt-get install -y gcc libffi-dev libssl-dev && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get clean

# Copy your application code
COPY . .

# Expose Flask port
EXPOSE 5000

# Run your Flask app
CMD ["python", "app.py"]
