# UniFi Network MCP server container image
#
# Multi-stage build producing a distroless image with no shell and no external
# binaries. The runtime has no package manager, no shell, and no GNU userland —
# only libc and the statically-linked server binary.
#
# Builder glibc generation must be ≤ runtime generation: Debian 13 (trixie) on
# both sides satisfies this. Building on a newer base (Debian 14+) would link
# against a newer glibc that the Debian 13 runtime does not carry.

# Source of libgcc-s1 only; the runtime is base-nossl, which lacks it. Not the
# runtime itself, so keep it ahead of the builder and out of the last FROM.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2 AS libgcc

# Builder stage: Debian 13 slim with Rust 1.98
# Pinned to the multi-arch image index digest resolved on 2026-09-29 (covers
# both linux/amd64 and linux/arm64; buildx picks the matching manifest for
# whichever platform it is building under --platform).
FROM rust:1.100-slim-trixie@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy workspace manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY rustunifimcp/Cargo.toml rustunifimcp/
COPY rustunifimcp-core/Cargo.toml rustunifimcp-core/

# Create stub main.rs files to cache dependencies
RUN mkdir -p rustunifimcp/src rustunifimcp-core/src && \
    echo 'fn main() {}' > rustunifimcp/src/main.rs && \
    echo '' > rustunifimcp-core/src/lib.rs && \
    cargo build --release && \
    rm -rf rustunifimcp/src rustunifimcp-core/src

# Copy source and build the real binary
COPY rustunifimcp/ rustunifimcp/
COPY rustunifimcp-core/ rustunifimcp-core/
RUN touch rustunifimcp/src/main.rs rustunifimcp-core/src/lib.rs && \
    cargo build --release --locked

# libgcc_s.so.1 is the one library the binary needs beyond glibc, and
# base-nossl does not ship it. Stage it with its dpkg records (status.d) so
# Trivy and the SBOM still see libgcc-s1 and gcc-14-base. The multiarch
# directory comes from the builder's own triplet (x86_64 or aarch64).
COPY --from=libgcc / /cc/
RUN triplet="$(gcc -dumpmachine | sed 's/-pc-/-/')" \
    && install -d "/stage-libgcc/usr/lib/${triplet}" /stage-libgcc/var/lib/dpkg/status.d \
    && cp -a "/cc/usr/lib/${triplet}/libgcc_s.so.1" "/stage-libgcc/usr/lib/${triplet}/" \
    && cp -a /cc/var/lib/dpkg/status.d/libgcc-s1 /cc/var/lib/dpkg/status.d/libgcc-s1.md5sums \
        /cc/var/lib/dpkg/status.d/gcc-14-base /cc/var/lib/dpkg/status.d/gcc-14-base.md5sums \
        /stage-libgcc/var/lib/dpkg/status.d/

# Runtime stage: distroless base-nossl, Debian 13, nonroot user. No
# libssl3t64/libcrypto: the binary is rustls-only, and libssl3t64 carries
# unfixed CVE-2026-124709. Multi-arch image index digest (linux/amd64 and
# linux/arm64).
FROM gcr.io/distroless/base-nossl-debian13:nonroot@sha256:4006ac92504be607b70de01d1f64f38288c69fcd8faa820f6d3aed266ea32ac5

# Run as nonroot user (UID 65532)
USER 65532:65532

# No HEALTHCHECK: distroless has no shell and no utilities, so there is nothing
# for a healthcheck command to run. Orchestrators supervise the process via the
# container runtime. Suppressed explicitly in .trivyignore.yaml (AVD-DS-0026)
# rather than silently, so the decision is reviewable.

COPY --from=builder /stage-libgcc/ /

# Copy the server binary
COPY --from=builder /build/target/release/rustunifimcp /usr/local/bin/rustunifimcp

# Metadata
LABEL org.opencontainers.image.title="rustunifimcp"
LABEL org.opencontainers.image.description="UniFi Network MCP server"
LABEL org.opencontainers.image.source="https://github.com/mechubsec/rustunifimcp"
LABEL org.opencontainers.image.licenses="MIT"
# Official MCP Registry ownership check: must equal server.json "name".
LABEL io.modelcontextprotocol.server.name="io.github.mechubsec/rustunifimcp"

# ENTRYPOINT carries what must always hold: config paths and anything security-
# relevant. CMD carries only what an operator is expected to replace: bind
# address, port, and mode flags. Docker replaces CMD when the caller supplies
# arguments, so security-relevant defaults must stay in ENTRYPOINT.
#
# --audit-hmac-key-file: this image is distroless with no shell, so a
# shell-script key-generation wrapper (as LXC's install.sh uses) can never
# run here. Instead the binary itself generates
# /var/lib/unifimcp/audit-hmac.key on first run if it is absent (see
# ensure_audit_hmac_key in src/main.rs) -- the container-image equivalent of
# install.sh's own key-generation step, closing the "5 of 6 server images
# run unkeyed audit" gap (mecmcp#376 / MEC-978). The path is under the
# writable /var/lib/unifimcp volume, not /etc/unifimcp, which is mounted
# read-only in every documented `docker run` example. --audit-redact still
# defaults to empty (redaction itself stays opt-in), so this alone does not
# change what is logged -- it only means the key is already there the
# moment an operator turns redaction on.
ENTRYPOINT ["/usr/local/bin/rustunifimcp", \
    "--controllers-file", "/etc/unifimcp/controllers.json", \
    "--tokens-file", "/var/lib/unifimcp/tokens.json", \
    "--state-file", "/var/lib/unifimcp/changesets.json", \
    "--audit-hmac-key-file", "/var/lib/unifimcp/audit-hmac.key"]
CMD ["--transport", "streamable-http", \
    "--host", "127.0.0.1", \
    "--port", "30033"]
