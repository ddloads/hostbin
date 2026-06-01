FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app

RUN addgroup -S hostbin && adduser -S hostbin -G hostbin

COPY app.py /app/app.py

RUN mkdir -p /data && chown -R hostbin:hostbin /app /data

USER hostbin

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/', timeout=2).read()"

CMD ["python", "app.py"]
