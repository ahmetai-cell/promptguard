FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download model at build time so runtime startup is instant
RUN python -c "from transformers import pipeline; pipeline('text-classification', model='ProtectAI/deberta-v3-base-prompt-injection-v2')"

COPY . .

ENV AUDIT_LOG=/data/audit.jsonl
ENV L2_BLOCK_THRESHOLD=0.80

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
