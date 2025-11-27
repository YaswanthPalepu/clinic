#!/bin/bash
set -e

# Cloud Run entrypoint script for Clinical BERT API
# Handles PORT environment variable and proper signal handling

# Use Cloud Run provided port or default 8080
PORT="${PORT:-8080}"
echo "Starting Clinical BERT API on port $PORT"

# Ensure PATH includes installed binaries
export PATH="/usr/local/bin:$PATH"

# Change to app directory
cd /code

# Run the app with exec for proper signal handling
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT" --workers "${WORKERS:-1}" --log-level "${LOG_LEVEL:-info}"
