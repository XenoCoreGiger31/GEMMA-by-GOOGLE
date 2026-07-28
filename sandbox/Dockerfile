FROM python:3.12-slim
RUN useradd -m -u 1000 runner \
 && pip install --no-cache-dir requests pwntools scapy
USER runner
WORKDIR /work
# scripts get mounted read-only at /work; output goes to stdout only
ENTRYPOINT ["python3"]
