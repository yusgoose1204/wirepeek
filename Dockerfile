FROM python:3.10-slim

RUN apt-get update && \
    apt-get install -y tshark curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

ENV PORT=5000
EXPOSE $PORT

CMD ["python", "wirepeek.py"]

