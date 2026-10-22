FROM python:3.12-slim
ARG RDS_CA_BUNDLE_SHA256
RUN test -n "$RDS_CA_BUNDLE_SHA256" \
 && mkdir -p /etc/mk \
 && python -c "import urllib.request; urllib.request.urlretrieve('https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem', '/etc/mk/rds-global-bundle.pem')" \
 && echo "$RDS_CA_BUNDLE_SHA256  /etc/mk/rds-global-bundle.pem" | sha256sum -c -
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
USER 65532:65532
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 CMD ["python", "-m", "app.healthcheck"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
