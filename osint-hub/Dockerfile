FROM python:3.11-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Clone OSINT tools
RUN git clone --depth 1 https://github.com/sherlock-project/sherlock.git \
 && git clone --depth 1 https://github.com/soxoj/maigret.git \
 && git clone --depth 1 https://github.com/megadose/holehe.git \
 && git clone --depth 1 https://github.com/p1ngul1n0/blackbird.git \
 && git clone --depth 1 https://github.com/thewhiteh4t/nexfil.git \
 && git clone --depth 1 https://github.com/qeeqbox/social-analyzer.git \
 && git clone --depth 1 https://github.com/laramies/theHarvester.git \
 && git clone --depth 1 https://github.com/sundowndev/phoneinfoga.git \
 && git clone --depth 1 https://github.com/khast3x/h8mail.git \
 && git clone --depth 1 https://github.com/Ekultek/WhatBreach.git \
 && git clone --depth 1 https://github.com/JoelGMSec/LeakSearch.git \
 && git clone --depth 1 https://github.com/D4Vinci/Cr3dOv3r.git \
 && git clone --depth 1 https://github.com/JoelGMSec/comb2passlist.git \
 && git clone --depth 1 https://github.com/smicallef/spiderfoot.git \
 && git clone --depth 1 https://github.com/mxrch/GHunt.git \
 && git clone --depth 1 https://github.com/s0md3v/Photon.git

# Install Python tool dependencies
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir \
    flask gunicorn requests \
    sherlock-project maigret holehe h8mail social-analyzer \
    ignorant \
 && (cd /opt/blackbird && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/nexfil && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/theHarvester && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/WhatBreach && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/LeakSearch && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/Cr3dOv3r && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/spiderfoot && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/Photon && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true)

# Copy OSINT Hub application
WORKDIR /opt/osint-hub
COPY . .

ENV OSINT_HOME=/opt
ENV PORT=8080
ENV HOST=0.0.0.0

EXPOSE 8080

# Use gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4", "--timeout", "600", "app:app"]
