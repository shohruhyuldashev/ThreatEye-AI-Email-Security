FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the backend files
COPY . .

# Production by default: multiple workers, no --reload. Set UVICORN_RELOAD=1 for a
# dev bind-mount with live reload, or UVICORN_WORKERS to tune the pool.
CMD ["sh", "-c", "if [ \"$UVICORN_RELOAD\" = \"1\" ]; then exec uvicorn main:app --host 0.0.0.0 --port 8000 --reload; else exec uvicorn main:app --host 0.0.0.0 --port 8000 --workers ${UVICORN_WORKERS:-2}; fi"]
