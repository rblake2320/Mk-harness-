# syntax=docker/dockerfile:1.7
# Multi-stage build for the MK action kernel. One image, four process types
# (mk-action-api, mk-outbox-relay, mk-action-worker, mk-audit-verifier) plus the
# operator tools mk-keyctl and mk-restore-gate run
# with distinct DB roles via MK_DATABASE_URL.
FROM rust:1.97.0-bookworm AS builder
WORKDIR /src
COPY rust/ rust/
COPY contracts/ contracts/
COPY migrations/ migrations/
WORKDIR /src/rust
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/rust/target \
    cargo build --release --locked --bins \
 && mkdir -p /out \
 && cp target/release/mk-action-api target/release/mk-outbox-relay target/release/mk-action-worker target/release/mk-audit-verifier target/release/mk-mcp-server target/release/mk-keyctl target/release/mk-restore-gate target/release/mk-healthcheck /out/

# Database CA bundle (RDS global bundle) baked in; fetched at build time and pinned by
# checksum supplied by the operator (`--build-arg RDS_CA_BUNDLE_SHA256=…`, from
# https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem). Without the arg the
# build fails closed: a production image must not ship an unverified trust anchor.
FROM debian:bookworm-slim AS cabundle
ARG RDS_CA_BUNDLE_URL=https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
ARG RDS_CA_BUNDLE_SHA256
RUN apt-get update -q && apt-get install -y -q --no-install-recommends ca-certificates curl >/dev/null \
 && test -n "$RDS_CA_BUNDLE_SHA256" \
 && curl -fsSL -o /rds-global-bundle.pem "$RDS_CA_BUNDLE_URL" \
 && echo "$RDS_CA_BUNDLE_SHA256  /rds-global-bundle.pem" | sha256sum -c -

# Minimal runtime: CA certs only, non-root numeric UID, no shell.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /out/ /usr/local/bin/
COPY --from=cabundle /rds-global-bundle.pem /etc/mk/rds-global-bundle.pem
USER 65532:65532
ENV RUST_LOG=info
# Read-only root FS, dropped capabilities and resource limits are set by the
# orchestrator (see docker-compose.kernel.yml / Kubernetes manifests).
ENTRYPOINT ["/usr/local/bin/mk-action-api"]
