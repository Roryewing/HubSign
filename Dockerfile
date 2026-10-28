FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY hubsign ./hubsign
RUN pip install --no-cache-dir . && mkdir -p /data
ENV HUBSIGN_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8000
# $PORT is set by Render/Heroku-style hosts; 8000 otherwise.
CMD hubsign --host 0.0.0.0 --port ${PORT:-8000}
