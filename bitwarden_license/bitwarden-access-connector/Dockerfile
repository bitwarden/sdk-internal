# Packages the bwac that build-access-connector.yml builds. The context holds one binary per
# platform, at linux/amd64/bwac and linux/arm64/bwac. The binaries link against glibc, and the
# arm64 one needs 2.39 or later.
FROM debian:13-slim

ARG TARGETPLATFORM

LABEL com.bitwarden.product="bitwarden"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 bwac \
    && useradd --system --uid 10001 --gid bwac --no-create-home --shell /usr/sbin/nologin bwac \
    && install -d -m 0755 /etc/bwac /opt/bwac/scripts

COPY --chmod=0755 ${TARGETPLATFORM}/bwac /usr/local/bin/bwac

USER 10001:10001

# bwac doesn't reap the processes a killed script leaves behind, so it can't be PID 1.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/bwac"]
CMD ["run"]
