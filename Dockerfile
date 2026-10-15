# syntax=docker/dockerfile:1.7
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
       ca-certificates curl git build-essential pkg-config cmake perl python3 unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /source
COPY .bazelversion ./
COPY scripts/install-bazel ./scripts/install-bazel
RUN bash scripts/install-bazel /usr/local/bin

COPY MODULE.bazel MODULE.bazel.lock BUILD.bazel .bazelrc .bazelignore Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/root/.cache/bazel,sharing=locked \
    bazel build --config=release --lockfile_mode=error //:hiro-proxy \
    && install -D -m 0755 bazel-bin/hiro-proxy /out/hiro-proxy

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS runtime

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --from=builder --chown=65532:65532 /out/hiro-proxy /usr/local/bin/hiro-proxy

USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/hiro-proxy"]
