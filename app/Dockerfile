# ---- Stage 1: Builder ----
FROM python:3.11-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/app/deps -r requirements.txt

# ---- Stage 2: Distroless runtime ----
FROM gcr.io/distroless/python3-debian12:nonroot

WORKDIR /app
COPY --from=builder /app/deps /app/deps
COPY app.py .

ENV PYTHONPATH=/app/deps
EXPOSE 8080

CMD ["app.py"]
