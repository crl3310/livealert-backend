FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --system --uid 1001 appuser && chown -R appuser /app
USER appuser
EXPOSE 8080
CMD ["gunicorn", "-c", "gunicorn.conf.py", "server:app"]
