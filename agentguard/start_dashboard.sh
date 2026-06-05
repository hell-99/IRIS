#!/bin/sh
# Startup script for the IRIS Streamlit dashboard.

set -e

mkdir -p data/logs

echo "Starting IRIS Dashboard..."
exec streamlit run dashboard/app.py \
    --server.port 8501 \
    --server.address 0.0.0.0 \
    --server.headless true \
    --theme.base dark \
    --theme.backgroundColor "#0a0e1a" \
    --theme.primaryColor "#00ff88" \
    --theme.textColor "#e2e8f0" \
    --logger.level error
