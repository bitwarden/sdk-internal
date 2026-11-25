# Packages the bwac that build-access-connector.yml builds. The context holds one binary per
# platform, at linux/amd64/bwac and linux/arm64/bwac. The binaries link against glibc, and the
# arm64 one needs 2.39 or later.

# Ubuntu ships tini in universe, which Canonical patches only with Ubuntu Pro, so it comes from
# tini's releases.
FROM scratch AS tini-amd64
ADD --checksum=sha256:c5b0666b4cb676901f90dfcb37106783c5fe2077b04590973b885950611b30ee \
    https://github.com/krallin/tini/releases/download/v0.19.0/tini-static-amd64 /tini

FROM scratch AS tini-arm64
ADD --checksum=sha256:eae1d3aa50c48fb23b8cbdf4e369d0910dfc538566bfd09df89a774aa84a48b9 \
    https://github.com/krallin/tini/releases/download/v0.19.0/tini-static-arm64 /tini

FROM tini-${TARGETARCH} AS tini

FROM ubuntu:24.04

ARG TARGETPLATFORM

LABEL com.bitwarden.product="bitwarden"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 bwac \
    && useradd --system --uid 10001 --gid bwac --no-create-home --shell /usr/sbin/nologin bwac \
    && install -d -m 0755 /etc/bwac /opt/bwac/scripts

COPY --from=tini --chmod=0755 /tini /usr/bin/tini
COPY --chmod=0755 ${TARGETPLATFORM}/bwac /usr/local/bin/bwac

USER 10001:10001

# bwac doesn't reap the processes a killed script leaves behind, so it can't be PID 1.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/bwac"]
CMD ["run"]
