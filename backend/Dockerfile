# Backend container for Vuln-Mapper.
# Ships Python + Bandit + Semgrep so the SAST engine works in the cloud.
# Deploy on Render, Railway, Fly.io, or any Docker host.

FROM python:3.12-slim

# git is handy for some semgrep rule fetches; build tools kept minimal.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (better layer caching).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend source.
COPY . .

# The platform (Render/Railway) injects $PORT; default to 8000 locally.
ENV PORT=8000
EXPOSE 8000

# Note: this serves the API. If you also want the container to serve the
# frontend, keep the StaticFiles mount in main.py and copy ../frontend in.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT}"]