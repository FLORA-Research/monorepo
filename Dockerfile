# Server image: build on musl, run from scratch.
#
# The build stage is Alpine so the toolchain is musl-native and the binary
# comes out fully static; the runtime stage is `scratch` because a static
# binary with no files, no shell, and no package manager is the smallest
# possible attack surface. Render and any Docker host run the same image.
#
# No BuildKit cache mounts: plain `docker build` builds this too, and the
# layer order (manifests and crates copy, then one build layer) keeps the
# common path cached on any builder.

FROM rust:1-alpine AS build
WORKDIR /repo

# Rust on Alpine needs a C toolchain for the linker.
RUN apk add --no-cache musl-dev

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --release -p flora-server && \
    cp target/release/flora-server /usr/local/bin/flora-server

FROM scratch
COPY --from=build /usr/local/bin/flora-server /flora-server

EXPOSE 8080
ENV RUST_LOG=flora_server=info
ENTRYPOINT ["/flora-server"]
