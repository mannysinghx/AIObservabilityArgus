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

# Dual-stack launcher (serves IPv4 + IPv6 on $PORT). IPv6 is required for
# Railway private networking; IPv4 for its health-check probe. See serve.py.
CMD ["python", "-m", "argus_detection.serve"]
