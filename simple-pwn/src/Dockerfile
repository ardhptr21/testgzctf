FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends supervisor make gcc libc6-dev socat vim-tiny nano \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Makefile chall.c /app/
RUN make compile
COPY supervisord.conf /etc/supervisord.conf

EXPOSE 8081
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
