FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends supervisor make vim-tiny nano \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py Makefile /app/
COPY supervisord.conf /etc/supervisord.conf

ARG FLAG="flag{simple_web_demo_flag}"
RUN printf '%s\n' "$FLAG" > /flag && chmod 444 /flag

EXPOSE 8080
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
