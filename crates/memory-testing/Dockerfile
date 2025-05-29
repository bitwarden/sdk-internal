###############################################
#                 Build stage                 #
###############################################
FROM rust:1.85 AS base
WORKDIR /app

# Make sure the correct rust toolchain is installed only once
COPY rust-toolchain.toml /app/
RUN rustup show

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
FROM debian:bookworm-slim

# This specifically needs to run as root to be able to capture core dumps
USER root

RUN apt-get update && apt-get install -y --no-install-recommends gdb=13.1-3 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy built project from the build stage and the cases.json file
COPY --from=build /app/target/release/memory-testing /app/target/release/capture-dumps ./
COPY crates/memory-testing/cases.json .

CMD [ "/capture-dumps", "./memory-testing", "/" ]
