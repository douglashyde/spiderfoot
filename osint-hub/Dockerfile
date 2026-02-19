FROM python:3.11-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget gcc g++ libffi-dev libxml2-dev libxslt1-dev \
    nmap whois dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Clone OSINT tools (each tolerant of failure so one dead repo doesn't block the build)
RUN git clone --depth 1 https://github.com/sherlock-project/sherlock.git || true
RUN git clone --depth 1 https://github.com/soxoj/maigret.git || true
RUN git clone --depth 1 https://github.com/megadose/holehe.git || true
RUN git clone --depth 1 https://github.com/p1ngul1n0/blackbird.git || true
RUN git clone --depth 1 https://github.com/thewhiteh4t/nexfil.git || true
RUN git clone --depth 1 https://github.com/qeeqbox/social-analyzer.git || true
RUN git clone --depth 1 https://github.com/laramies/theHarvester.git || true
RUN git clone --depth 1 https://github.com/sundowndev/phoneinfoga.git || true
RUN git clone --depth 1 https://github.com/khast3x/h8mail.git || true
RUN git clone --depth 1 https://github.com/Ekultek/WhatBreach.git || true
RUN git clone --depth 1 https://github.com/JoelGMSec/LeakSearch.git || true
RUN git clone --depth 1 https://github.com/D4Vinci/Cr3dOv3r.git || true
RUN git clone --depth 1 https://github.com/smicallef/spiderfoot.git || true
RUN git clone --depth 1 https://github.com/mxrch/GHunt.git || true
RUN git clone --depth 1 https://github.com/s0md3v/Photon.git || true

# Install Python tool dependencies
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir \
    flask gunicorn requests beautifulsoup4 \
    sherlock-project maigret holehe h8mail social-analyzer \
    ignorant socialscan \
 && (cd /opt/blackbird && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/nexfil && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/theHarvester && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/WhatBreach && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/LeakSearch && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/Cr3dOv3r && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/spiderfoot && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/Photon && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true) \
 && (cd /opt/GHunt && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true)

# Copy OSINT Hub application
WORKDIR /opt/osint-hub
COPY . .

ENV OSINT_HOME=/opt
ENV PORT=8080
ENV HOST=0.0.0.0

EXPOSE 8080

# Use gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4", "--timeout", "600", "app:app"]
