FROM python:3.12-alpine
WORKDIR /app
COPY server ./
ENV DEBUG_MODE=false \
    LOG_FILE='logs/tracking.log' \
    WEBHOOK_URL='' \
    MAX_LOG_SIZE=10485760 \
    BACKUP_COUNT=5 \
    ENABLE_GEOLOCATION=True \
    DATA_FILE='data/tracking_data.json' \
    MAX_DATA_ENTRIES=10000

RUN pip install -r requirements.txt
EXPOSE 8080
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "app:app"]