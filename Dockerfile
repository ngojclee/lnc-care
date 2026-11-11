FROM rust:1-slim-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock VERSION ./
COPY src ./src
RUN cargo build --release --locked --bin lnc-care \
    && strip /src/target/release/lnc-care

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 lnccare \
    && useradd -u 10001 -g 10001 -M -d /app -s /usr/sbin/nologin lnccare
WORKDIR /app
COPY --from=builder /src/target/release/lnc-care /app/lnc-care
COPY public /app/public
COPY VERSION /app/VERSION
RUN chown -R 10001:10001 /app
ENV DATA_DIR=/data PUBLIC_DIR=/app/public
USER 10001:10001
EXPOSE 8000
CMD ["/app/lnc-care", "serve"]
