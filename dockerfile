# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set environment variables to prevent Python buffering and use a non-root user (for production)
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Create and set the working directory
WORKDIR /app

# Install system dependencies if needed (e.g., for building certain Python packages)
RUN apt-get update && apt-get install -y build-essential

# Copy requirements.txt and install Python dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of the project files into the container
COPY . /app/

# Expose any necessary ports (if you run a web server or API; otherwise, not needed)
# EXPOSE 8000

# Define the default command to run your dashboard (or main application)
CMD ["python", "dashboards/threat_dashboard.py"]
