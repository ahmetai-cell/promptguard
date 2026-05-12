FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 120 \
    torch==2.4.1+cpu --extra-index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir --timeout 120 \
    fastapi==0.115.0 "uvicorn[standard]==0.30.6" pydantic==2.8.2 transformers==4.44.2

# Pre-download model at build time so runtime startup is instant
RUN python -c "from transformers import pipeline; pipeline('text-classification', model='ProtectAI/deberta-v3-base-prompt-injection-v2')"

COPY . .

ENV AUDIT_LOG=/data/audit.jsonl
ENV L2_BLOCK_THRESHOLD=0.80

EXPOSE 8000

CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT:-8000}"]
