FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY alembic.ini .
COPY alembic ./alembic
COPY app ./app
COPY contracts ./contracts
COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh
EXPOSE 8000
ENTRYPOINT ["./docker-entrypoint.sh"]
