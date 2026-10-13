#!/bin/sh
# Builds the Galactus gVisor release tarball: the official upstream release
# tarball with gvisor-bin/gvisor_sentry rebuilt from this branch, which is the
# `go` branch commit of that release plus the overlay fixes on top of it.
# Every other member (runsc, the containerd shim, the other sidecars) is the
# upstream binary, byte for byte.
#
# usage: galactus/build-release.sh OUTDIR
# Writes OUTDIR/gvisor.tar.bz2 and OUTDIR/gvisor.tar.bz2.sha512. Needs docker.
# The build is reproducible: same branch commit, same output checksum.
set -eu

UPSTREAM_RELEASE=20261005
UPSTREAM_SHA512=79869ae9a589355a46d46fdac068d9a954e741741ffe77c64e38c56ea955498c1cb04e9bce44e1cce5155333e6b76bee72347c6661bb7c78fd2fe3aad198c8fe
# runsc refuses sidecars whose release label differs from its own.
VERSION_LABEL=release-${UPSTREAM_RELEASE}.0
GO_IMAGE=golang:1.27.2-trixie@sha256:47667934874913a449b96faa7ef4777fa285d9ec29126ee80ed61c45b7cccf0e

out=$(cd "${1:?usage: $0 OUTDIR}" && pwd)
src=$(cd "$(dirname "$0")/.." && pwd)

docker run --rm --network=host -v "$src:/src:ro" -v "$out:/out" -w /src "$GO_IMAGE" sh -euc "
  apt-get -qq update >/dev/null && apt-get -qq install -y --no-install-recommends bzip2 >/dev/null
  curl -fsSL -o /tmp/upstream.tar.bz2 \
    https://storage.googleapis.com/gvisor/releases/release/$UPSTREAM_RELEASE/x86_64/gvisor.tar.bz2
  echo '$UPSTREAM_SHA512  /tmp/upstream.tar.bz2' | sha512sum -c
  mkdir /tmp/rel && tar -xjf /tmp/upstream.tar.bz2 -C /tmp/rel

  export GOCACHE=/tmp/gocache GOMODCACHE=/tmp/gomod
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
    -ldflags '-X gvisor.dev/gvisor/runsc/version.version=$VERSION_LABEL' \
    -o /tmp/rel/gvisor-bin/gvisor_sentry ./runsc/cmd/sentry
  chmod 0755 /tmp/rel/gvisor-bin/gvisor_sentry

  # Same members, order, owner and mtime as the upstream tarball.
  cd /tmp/rel
  tar --format=gnu --numeric-owner --owner=0 --group=0 --mtime='2000-01-01 00:00:00Z' \
    --no-recursion -cf /tmp/gvisor.tar \
    containerd-shim-runsc-v1 runsc gvisor-bin \
    gvisor-bin/checkpointgofer gvisor-bin/gvisor-sentry-prewarmer gvisor-bin/gvisor_sentry \
    gvisor-bin/runsc-fd-parking gvisor-bin/runsc-metric-server
  bzip2 -9 -c /tmp/gvisor.tar > /out/gvisor.tar.bz2
  cd /out && sha512sum gvisor.tar.bz2 > gvisor.tar.bz2.sha512
"
