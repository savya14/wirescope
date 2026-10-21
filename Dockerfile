# ---- Stage 1: build the React frontend -------------------------------------
FROM node:22-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: FastAPI backend that also serves the built frontend ----------
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 DEBIAN_FRONTEND=noninteractive
# tshark gives PyShark full application-layer dissection (Scapy is the fallback)
RUN apt-get update \
    && echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY backend/ backend/
COPY parser.py detection.py generate_sample.py generate_scenarios.py sample.pcap ./
COPY scenarios/ scenarios/
COPY --from=frontend /app/frontend/dist frontend/dist
RUN useradd --create-home app && mkdir -p data/sessions && chown -R app:app /app
USER app
ENV SESSIONS_DIR=/app/data/sessions
EXPOSE 8000
CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
