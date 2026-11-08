#!/bin/bash
# Usage: build.sh rootfs|eif <source tar> <version> <environment> <out dir>
# eif builds an arm64 image. nitro-cli takes its kernel from its own architecture, so on an x86_64 Docker server it
# takes the arm64 kernel from nitro-cli's aarch64 package and runs linuxkit for arm64. It also copies out the
# nitro-cli and allocator it built with, which the arm64 hosts run, since Ubuntu packages neither. On x86_64 those
# two are x86_64 binaries, so that out dir holds the right image but is not a bundle a host can run.
# A nitro-cli bump moves both amazonlinux digests, nitro_cli, and the aarch64 RPM's name and SHA-256 together.
set -euo pipefail
step=$1 src=$2 version=$3 environment=$4
out=$(mkdir -p "$5" && cd "$5" && pwd)
src=$(cd "$(dirname "$src")" && pwd)/$(basename "$src")
golang=public.ecr.aws/docker/library/golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5
amazonlinux=public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:b14d3c9680e4f240c8aa2117f4d4c815a996a7d5b8d266b1113393d2acf92e7b
amazonlinux_amd64=public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:c0b8ebe9081ee3bd6aa827748a61303b5a31595e0f4ff4b2db3b48f1f549d453
nitro_cli=1.5.0
devel_aarch64=aws-nitro-enclaves-cli-devel-1.5.0-0.amzn2023.aarch64.rpm
devel_aarch64_sha256=028013b5832dfef516ae25786a99465401ec7ad5e0a316f7bad0a792d6512284
arch=$(docker version --format '{{.Server.Arch}}')
[ "$arch" != amd64 ] || amazonlinux=$amazonlinux_amd64
mirrored() {
  local name=${1##*/}
  local copy=${IMAGE_MIRROR:-}/${name%%[:@]*}@${1#*@}
  if [ -n "${IMAGE_MIRROR:-}" ] && docker pull -q "$copy" >/dev/null; then echo "$copy"; else echo "$1"; fi
}
golang=$(mirrored "$golang") amazonlinux=$(mirrored "$amazonlinux")
veil_commit=$(cat "$(dirname "$0")/veil-commit")

rm -rf "$out/rootfs" "$out/rootfs.tar"
docker run --rm -v "$src:/src.tar:ro" -v "$out:/out" -e VERSION="$version" -e ENVIRONMENT="$environment" -e VEIL="$veil_commit" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" "$golang" bash -euo pipefail -c '
  mkdir /build && tar -xf /src.tar -C /build && cd /build
  export CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOFLAGS="-trimpath -buildvcs=false"
  root=/out/rootfs
  go build -o $root/worker ./cmd/worker
  go build -o $root/enclave ./cmd/enclave
  git clone -q https://github.com/Amnesic-Systems/veil /veil && git -C /veil checkout -q "$VEIL"
  (cd /veil && go build -o $root/veil-daemon ./cmd/veil-daemon && go build -o /out/veil-proxy ./cmd/veil-proxy)
  GOOS= GOARCH= go run ./cmd/enclave --credentials routes.json >/out/credentials.txt
  install -D -m 0644 /etc/ssl/certs/ca-certificates.crt $root/etc/ssl/certs/ca-certificates.crt
  install -m 0644 routes.json $root/routes.json
  install -m 0644 deploy/enclave/$ENVIRONMENT.env /out/image.env
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=posix \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime -C $root -cf /out/rootfs.tar .
  sha256sum /out/rootfs.tar | cut -d" " -f1 >/out/rootfs.sha256
  chown -R "$HOST_UID:$HOST_GID" /out/rootfs /out/rootfs.tar /out/rootfs.sha256 /out/image.env /out/veil-proxy /out/credentials.txt'
echo "rootfs sha256 $(cat "$out/rootfs.sha256")"
[ "$step" = eif ] || exit 0

image=morse-enclave:$(cut -c1-16 "$out/rootfs.sha256")
settings=()
while IFS= read -r line; do settings+=(-c "ENV $line"); done <"$out/image.env"
docker import --platform linux/arm64 "${settings[@]}" \
  -c 'ENTRYPOINT ["/veil-daemon", "-app-cmd", "/enclave /worker", "-int-port", "8081", "-dns-resolver", "10.0.0.1", "-vsock-port", "1024", "-enclave-code-uri", "https://github.com/trymorse/morse-enclave"]' \
  "$out/rootfs.tar" "$image" >/dev/null
blobs=
[ "$arch" != amd64 ] || blobs="dnf install -y -q dnf-plugins-core cpio >/dev/null
  mkdir /tmp/arm64 /blobs
  cd /tmp/arm64
  dnf download -q --forcearch=aarch64 ${devel_aarch64%.rpm}
  echo '$devel_aarch64_sha256  $devel_aarch64' | sha256sum -c --quiet
  rpm2cpio $devel_aarch64 | cpio -idm --quiet
  cd usr/share/nitro_enclaves/blobs
  cp Image /blobs/bzImage
  cp Image.config /blobs/bzImage.config
  cp cmdline init nsm.ko /blobs/
  cd /
  printf '#!/bin/sh\nexec /usr/share/nitro_enclaves/blobs/linuxkit \"\$@\" --arch arm64\n' >/blobs/linuxkit
  chmod +x /blobs/linuxkit
  export NITRO_CLI_BLOBS=/blobs
  "
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$out:/out" -e IMAGE="$image" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  "$amazonlinux" bash -euo pipefail -c "
  dnf install -y -q aws-nitro-enclaves-cli-$nitro_cli aws-nitro-enclaves-cli-devel-$nitro_cli >/dev/null
  mkdir -p /tmp/artifacts
  ${blobs}NITRO_CLI_ARTIFACTS=/tmp/artifacts nitro-cli build-enclave --docker-uri \"\$IMAGE\" --output-file /out/proxy.eif >/out/measurements.json
  install -m 0755 /usr/bin/nitro-cli /usr/bin/nitro-enclaves-allocator /out/
  chown \"\$HOST_UID:\$HOST_GID\" /out/proxy.eif /out/measurements.json /out/nitro-cli /out/nitro-enclaves-allocator"
jq -c .Measurements "$out/measurements.json"
