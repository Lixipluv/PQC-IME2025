FROM ubuntu:22.04

# Install system dependencies required for compiling OpenSSL, liboqs and oqs-provider
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    curl \
    perl \
    python3 \
    python3-pip \
    jq \
    pkg-config \
    ca-certificates \
    zlib1g-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install OpenSSL (3.x series) from source.  We build our own
# copy so that we can later link the OQS provider against it.  The
# -Wl,-rpath ensures that the runtime linker can locate our OpenSSL
# libraries without the need to set LD_LIBRARY_PATH when running.
ARG OPENSSL_VERSION=3.3.1
RUN set -eux; \
    cd /tmp; \
    curl -LO https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz; \
    tar xzf openssl-${OPENSSL_VERSION}.tar.gz; \
    cd openssl-${OPENSSL_VERSION}; \
    ./Configure linux-x86_64 \
        --prefix=/usr/local \
        --openssldir=/usr/local/ssl \
        -Wl,-rpath,/usr/local/lib \
        shared \
        zlib-dynamic; \
    make -j"$(nproc)"; \
    make install_sw install_ssldirs; \
    ldconfig; \
    rm -rf /tmp/openssl-${OPENSSL_VERSION}*

# Build and install liboqs (post‑quantum primitives).  We disable the
# OpenSSL wrapper because we will be using the oqs-provider instead.
RUN set -eux; \
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs; \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_USE_OPENSSL=OFF \
      -DOQS_BUILD_ONLY_LIB=ON; \
    ninja -C /tmp/liboqs/build; \
    ninja -C /tmp/liboqs/build install; \
    ldconfig; \
    rm -rf /tmp/liboqs

# Build and install the oqs-provider.  This requires that liboqs and
# OpenSSL have already been installed.  The provider will be placed
# under /usr/local/lib64/ossl-modules.
RUN set -eux; \
    git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git /tmp/oqs-provider; \
    cmake -S /tmp/oqs-provider -B /tmp/oqs-provider/build -GNinja \
      -DCMAKE_PREFIX_PATH=/usr/local \
      -DOPENSSL_ROOT_DIR=/usr/local; \
    ninja -C /tmp/oqs-provider/build; \
    ninja -C /tmp/oqs-provider/build install; \
    ldconfig; \
    rm -rf /tmp/oqs-provider

# Try to build and install pyoqs (Python bindings for liboqs) as a fallback.
# If this fails, the application will still work but key generation via OpenSSL
# must succeed. We make this optional since the repository may not be accessible.
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends \
        python3-dev \
        swig \
        && rm -rf /var/lib/apt/lists/* || true; \
    cd /tmp && \
    (git clone --depth 1 https://github.com/open-quantum-safe/pyoqs.git pyoqs 2>/dev/null && \
     cd pyoqs && \
     (pip3 install --no-cache-dir . 2>/dev/null || python3 setup.py install 2>/dev/null || true) && \
     cd /tmp && rm -rf pyoqs) || \
    echo "Note: pyoqs installation skipped (not critical)"

# Set the environment so that OpenSSL can find the OQS provider module
ENV OPENSSL_MODULES=/usr/local/lib64/ossl-modules
ENV OSSL_PROVIDER_PATH=/usr/local/lib64/ossl-modules

# Set library path to use our compiled OpenSSL instead of system libraries
ENV LD_LIBRARY_PATH=/usr/local/lib64:/usr/local/lib:$LD_LIBRARY_PATH

# Ensure our OpenSSL binary is found first in PATH
ENV PATH=/usr/local/bin:$PATH

# Set PYTHONPATH so that Python can find the app module
ENV PYTHONPATH=/app

# Copy application code into the container
WORKDIR /app
COPY app/ /app/app/

# Install Python dependencies.  We upgrade pip and setuptools first
# before installing our requirements.  Installing with no cache
# reduces image size.
RUN pip3 install --no-cache-dir --upgrade pip setuptools wheel && \
    pip3 install --no-cache-dir -r /app/app/requirements.txt

# Expose the port used by the FastAPI server
EXPOSE 3030

# Run the application using uvicorn.  Host 0.0.0.0 binds to all
# interfaces so that the container is accessible from the host.  We
# disable access log to reduce verbosity.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "3030", "--no-access-log"]