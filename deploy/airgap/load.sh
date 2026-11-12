#!/bin/sh
# Loads the scanent image for this machine from an unpacked bundle. No network.
#
#   ./load.sh
#
#   CONTAINER_RUNTIME   docker (default), podman or nerdctl
#
# It runs verify.sh first and stops if that fails, picks the archive for this
# machine's architecture, loads it, and tags it ghcr.io/rodnapamet/scanent:<version>
# so the Compose files and the chart find it without a registry.
set -eu

cd "$(dirname "$0")"
./verify.sh

VERSION="$(cat VERSION)"
RUNTIME="${CONTAINER_RUNTIME:-docker}"
machine="$(uname -m)"
case "$machine" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *)
        echo "load: no scanent image for this machine's architecture: $machine" >&2
        exit 1
        ;;
esac

file=""
ref=""
while read -r a f r; do
    if [ "$a" = "$arch" ]; then
        file="$f"
        ref="$r"
    fi
done < images/IMAGES
[ -n "$file" ] && [ -f "$file" ] || { echo "load: the bundle holds no image for $arch" >&2; exit 1; }

"$RUNTIME" load -i "$file"
IMAGE="ghcr.io/rodnapamet/scanent:$VERSION"
if [ "$ref" != "$IMAGE" ]; then
    "$RUNTIME" tag "$ref" "$IMAGE"
fi

cat <<TEXT

loaded: $IMAGE  (linux/$arch)

Next, with the directory \`scanent init\` writes mounted at /etc/scanent:

  mkdir -p scanent scanent-out && chmod 0700 scanent scanent-out
  $RUNTIME run --rm -it --network none --user "\$(id -u):\$(id -g)" \\
    --read-only --cap-drop ALL --security-opt no-new-privileges \\
    -v "\$PWD/scanent:/etc/scanent" $IMAGE init --dir /etc/scanent

docs/quick-start.md has the rest.
TEXT
