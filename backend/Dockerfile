FROM python:3.13-alpine@sha256:c50ccfb66e5cc97a610dcd0b9597de6ef5b52c96280b51997b353a0fc87a8361 AS dependencies
ARG RDS_CA_BUNDLE_SHA256
RUN test -n "$RDS_CA_BUNDLE_SHA256" \
 && mkdir -p /etc/mk \
 && python -c "import urllib.request; urllib.request.urlretrieve('https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem', '/etc/mk/rds-global-bundle.pem')" \
 && echo "$RDS_CA_BUNDLE_SHA256  /etc/mk/rds-global-bundle.pem" | sha256sum -c -
COPY requirements-runtime.lock .
RUN pip install --no-cache-dir --upgrade pip==26.2.2 \
 && pip install --no-cache-dir --require-hashes --only-binary=:all: --target /packages -r requirements-runtime.lock

# Keep installer-vendored libraries and test dependencies out of the runtime.
# The interpreter and musl wheel ABI match the dependency builder exactly.
FROM python:3.13-alpine@sha256:c50ccfb66e5cc97a610dcd0b9597de6ef5b52c96280b51997b353a0fc87a8361
RUN python -m pip uninstall --yes pip
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app:/packages
COPY --from=dependencies /packages /packages
COPY --from=dependencies /etc/mk/rds-global-bundle.pem /etc/mk/rds-global-bundle.pem
COPY app ./app
USER 65532:65532
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 CMD ["python", "-m", "app.healthcheck"]
ENTRYPOINT []
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
