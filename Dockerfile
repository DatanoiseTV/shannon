# syntax=docker/dockerfile:1.7

# ----- builder ---------------------------------------------------------------
# Pin to the Debian release shannon's .deb is built against so libc /
# libssl SONAMEs match what the runtime stage installs.
FROM rust:1-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm llvm-dev libclang-dev libelf-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# bpf-linker needs the rust-src component on a nightly toolchain — the
# build.rs inside shannon shells out to `rustup run nightly cargo build`
# for the eBPF crate.
RUN rustup toolchain install nightly --component rust-src \
    && cargo install bpf-linker --locked

WORKDIR /src
COPY . .
RUN cargo build --release -p shannon

# ----- runtime ---------------------------------------------------------------
# debian:bookworm-slim instead of distroless because shannon dlopens
# libssl / libgnutls / libsqlite3 at runtime to attach uprobes; those
# need to be present on the same filesystem.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 libgnutls30 libsqlite3-0 libelf1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/shannon /usr/bin/shannon

# Default to the recorder so the image is useful as-is in a DaemonSet.
# Override the entrypoint with `shannon trace …` etc. for ad-hoc use.
ENTRYPOINT ["/usr/bin/shannon"]
CMD ["record", "--output", "/var/lib/shannon/capture.jsonl.zst", "--rotate", "200M"]

LABEL org.opencontainers.image.title="shannon"
LABEL org.opencontainers.image.description="Zero-instrumentation L7 observability via eBPF"
LABEL org.opencontainers.image.source="https://github.com/DatanoiseTV/shannon"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"
