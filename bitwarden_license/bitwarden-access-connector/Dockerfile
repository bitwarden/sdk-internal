# bwac builds in the Cargo workspace, so the context must be the repository root:
#   docker build -f bitwarden_license/bitwarden-access-connector/Dockerfile .

###############################################
#                 Build stage                 #
###############################################
FROM rust:1.99-alpine AS build

RUN apk add --no-cache gcc musl-dev

WORKDIR /source

COPY rust-toolchain.toml ./
RUN rustup toolchain install

COPY . ./

# Rust links musl statically, so the binary runs on any base image.
RUN cargo build -p bitwarden-access-connector --release --locked \
    && cp target/release/bwac /bwac

###############################################
#                  App stage                  #
###############################################
FROM alpine:3.24

LABEL com.bitwarden.product="bitwarden"

RUN apk add --no-cache ca-certificates tini \
    && addgroup -S -g 10001 bwac \
    && adduser -S -D -H -u 10001 -G bwac -s /sbin/nologin bwac \
    && install -d -m 0755 /etc/bwac /opt/bwac/scripts

COPY --from=build /bwac /usr/local/bin/bwac

USER 10001:10001

# bwac doesn't reap the processes a killed script leaves behind, so it can't be PID 1.
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/bwac"]
CMD ["run"]
