FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    inotify-tools \
    && rm -rf /var/lib/apt/lists/*

COPY . /app

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
        watchdog \
        flask \
        requests \
        cryptography \
        numpy \
        psutil \
        scikit-learn

RUN mkdir -p logs data CSV_logs certs keys temp

EXPOSE 5000

CMD ["python", "main.py", "--docker"]
