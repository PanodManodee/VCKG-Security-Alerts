FROM python:3.12-slim

WORKDIR /app
COPY asset_kg/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY asset_kg /app/asset_kg

# lab/ (the input CSVs) is mounted by docker-compose.asset.yml, so edits need no rebuild.
# Default: load -> link -> validate -> stats, then exit.
CMD ["python", "-m", "asset_kg", "all"]
