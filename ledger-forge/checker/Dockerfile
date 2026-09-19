FROM python:3.12-alpine

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY checker.py checks.py run.py ./
EXPOSE 8081

# V2-only persistent contract: /healthz advertises protocolVersion=2 and
# flagPlacement=platform-v1 and groupedRounds=true. POST /check requires
# roundStartTick: only Tick 1 initializes a new flag; every tick verifies
# functionality and all retained flags. The platform supplies placement state, so
# replacement pods never recreate old records or need a local state volume.
# GZCTF_CHECKER_TOKEN is mandatory. Challenge-specific hooks are in checks.py.
ENTRYPOINT ["python3", "run.py"]
