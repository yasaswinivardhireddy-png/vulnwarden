FROM python:3.8-slim-buster

ENV PAYMENT_API_KEY=demo-not-a-real-key-7f3a9c
WORKDIR /app
ADD https://example.com/tools/healthcheck.tar.gz /opt/healthcheck/

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shop/ shop/

EXPOSE 8000
CMD ["python", "-m", "shop.web"]
