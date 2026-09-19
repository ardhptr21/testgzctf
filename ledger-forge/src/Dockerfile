FROM python:3.11-slim

# Keep out of the host's daily `docker image prune -af` (the prune cron
# excludes label org.gzctf.keep=true).
LABEL org.gzctf.keep="true"

# supervisor as PID 1 (see supervisord.conf) so the service can be restarted in
# place without the container exiting — the team's defensive patches survive.
RUN apt-get update \
    && apt-get install -y --no-install-recommends supervisor \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py /app/app.py
COPY supervisord.conf /etc/supervisord.conf

# V2 flags are private ledger records created through the ordinary service API.
# Preserve this directory when replacing a container; process restarts retain it.
ENV LEDGER_DATA_DIR=/app/data
RUN mkdir -p /app/data
EXPOSE 8080
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
