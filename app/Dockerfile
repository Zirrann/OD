FROM python:3.10-slim

RUN pip install --upgrade pip
WORKDIR /app

COPY . .
RUN pip install --no-cache-dir -r app/requirements.txt

EXPOSE 5000

CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5000", "main:app"]