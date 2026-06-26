FROM python:3.12-slim
WORKDIR /service
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
ENV PYTHONUNBUFFERED=1
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8090/health')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
