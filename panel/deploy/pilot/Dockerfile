# Prebuilt binaries: no compilation or package installation on the target host.
FROM golang:1.27.1-bookworm@sha256:8d48e12ec56735e9358640898b9d9b9fcca110612ed8a5567438c0a1baa24e66 AS certificates
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY artifacts/bin/ /app/
COPY web/dist/ /app/web/
COPY deploy/licenses/ /app/licenses/
# Packaging normalizes public asset permissions before this build. No RUN
# instructions: cross-architecture images need no emulation or target execution.
WORKDIR /app
USER 65532:65532
ENTRYPOINT ["/app/panel-api"]
