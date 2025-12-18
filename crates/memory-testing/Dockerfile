###############################################
#                 Build stage                 #
###############################################
FROM rust:1.90-alpine AS base
WORKDIR /app

# Make sure the correct rust toolchain is installed only once
COPY rust-toolchain.toml /app/
RUN rustup show

# Install build dependencies for Alpine
RUN apk add --no-cache build-base linux-headers musl-dev libc-dev

# Install cargo-chef, to cache dependency builds
RUN cargo install cargo-chef --version 0.1.71 --locked

# Prepare the recipe for the dependencies, which will be built as the first part of the next stage
FROM base AS planner
COPY . /app/
RUN cargo chef prepare --recipe-path recipe.json

# Build dependencies based on the recipe of the previous stage, then copy the source and build the project
FROM base AS build
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook -p memory-testing --release --recipe-path recipe.json

# Copy the source here to reuse the cached dependencies
COPY . /app/
RUN cargo build -p memory-testing --release

###############################################
#                  App stage                  #
###############################################
FROM alpine:3.22

# This specifically needs to run as root to be able to capture core dumps
USER root

RUN apk add --no-cache gdb=15.2-r0

# Copy built project from the build stage and the cases.json file
COPY --from=build /app/target/release/memory-testing /app/target/release/capture-dumps ./
COPY crates/memory-testing/cases.json .

CMD [ "/capture-dumps", "./memory-testing", "/" ]
