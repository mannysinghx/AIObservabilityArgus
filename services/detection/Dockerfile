# Argus detection service. Build context = repo root (or services/detection).
#   docker build -f services/detection/Dockerfile -t argus-detection .
FROM python:3.12-slim

WORKDIR /app

# Install the package (heuristics + L4 only; L2 model deps are the optional
# ".[l2]" extra — enable by rebuilding with that extra and DETECTION_ENABLE_L2).
COPY services/detection/pyproject.toml ./pyproject.toml
COPY services/detection/argus_detection ./argus_detection
RUN pip install --no-cache-dir -e .

ENV PORT=8000
EXPOSE 8000

# Binds $PORT (Railway/Render) or falls back to 8000.
CMD ["sh", "-c", "uvicorn argus_detection.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
