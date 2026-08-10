FROM rust:1-alpine3.20 AS builder

RUN apk add --no-cache musl-dev build-base

WORKDIR /app
COPY Cargo.toml Cargo.loc[k] ./
COPY src ./src
RUN cargo generate-lockfile && cargo build --release

FROM alpine:3.20 AS runtime

RUN apk add --no-cache \
    tor \
    su-exec \
    ca-certificates \
    libgcc

RUN addgroup -S onion-tor && adduser -S -G onion-tor -h /var/lib/onion onion-tor

COPY --from=builder /app/target/release/onion-forum /usr/local/bin/onion-forum
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY save-tor-key.sh /usr/local/bin/save-tor-key.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh /usr/local/bin/save-tor-key.sh

WORKDIR /app
COPY templates ./templates
COPY static ./static

RUN mkdir -p /data && chown -R root:root /data

ENV PORT=8080
ENV FORUM_DB_PATH=/data/forum.db

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
