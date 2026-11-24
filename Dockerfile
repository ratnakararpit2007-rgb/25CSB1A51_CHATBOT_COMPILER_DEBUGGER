FROM debian:bookworm-slim

# Install multi-language compilers, interpreters, and debuggers:
# - C / C++: gcc, g++, lldb
# - Python: python3
# - Java: default-jdk-headless (javac + java)
# - JavaScript: nodejs
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        lldb \
        python3 \
        default-jdk-headless \
        nodejs \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /work \
    && chown 65534:65534 /work

WORKDIR /work
USER 65534:65534

# Container is started with `sleep` by sandbox_runner.py, then docker exec compilers/runtimes.
CMD ["sleep", "infinity"]
