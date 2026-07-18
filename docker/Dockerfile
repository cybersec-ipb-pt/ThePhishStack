# ==========================================
# STAGE 1: Build & Compile Dependencies
# ==========================================
FROM debian:trixie-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/thephish && chown -R www-data:www-data /opt/thephish

USER www-data

RUN python3 -m venv /opt/thephish/.venv

COPY src/requirements.txt /opt/thephish/requirements.txt

RUN /opt/thephish/.venv/bin/python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel \
    && /opt/thephish/.venv/bin/python3 -m pip install --no-cache-dir -r /opt/thephish/requirements.txt

# ==========================================
# STAGE 2: Final Minimal Runtime Image
# ==========================================
FROM debian:trixie-slim

ENV DFIR_IRIS_URL=https://example.com

ENV CORTEX_URL=https://example.com

ENV ROOT_PATH=""

ENV EVENTLET_TESTS=1

RUN apt-get update && apt-get upgrade -y && apt-get autoremove -y && apt-get install -y --no-install-recommends \
       ca-certificates \
       python3 \
       libmagic1 \
       netbase \
       gettext-base \
    && rm -rf /var/lib/apt/lists/*

COPY src/ /opt/thephish/

RUN chmod 774 /opt/thephish/entrypoint.sh && chown -R www-data:www-data /opt/thephish

USER www-data

COPY --from=builder /opt/thephish/.venv /opt/thephish/.venv

WORKDIR /opt/thephish

EXPOSE 8080

ENTRYPOINT ["/opt/thephish/entrypoint.sh"]