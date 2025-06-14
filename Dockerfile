# Use an official lightweight Python image.
FROM python:3.12-slim

# Set environment variables
ENV PYTHONUNBUFFERED True
ENV APP_HOME /app
WORKDIR $APP_HOME

# Install production dependencies.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy local code to the container image.
COPY . .

# Run the web service on container startup.
# Gunicorn is a professional-grade web server for Python.
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 main:app
