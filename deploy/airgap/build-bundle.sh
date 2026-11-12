#!/usr/bin/env bash
# Packages scanent for a site with no registry and no internet: two image
# archives, the Compose files, the chart, the examples and the documents, with
# a checksum for every file.
#
#   deploy/airgap/build-bundle.sh <version> <amd64-image-ref> <arm64-image-ref> <out-dir>
#
# It builds nothing and pulls nothing: both images must already be in the local
# image store (`docker build`, or `docker load` of a release's archives), and
# each must be of the architecture its argument says. It writes
#
#   <out-dir>/scanent-<version>-airgap/      the tree (README.md here lists it)
#   <out-dir>/scanent-<version>-airgap.tar   the same, as one archive
#
#   CONTAINER_RUNTIME   docker (default), podman or nerdctl
#   SOURCE_DATE_EPOCH   the modification time written into the archives.
#                       Default: the last commit's time. Two builds from the
#                       same inputs then differ only in what the runtime's
#                       `save` writes.
#   SCANENT_SBOM_CMD    optional. A command run once per image, with the image
#                       reference as its last argument; its standard output is
#                       stored as sbom/<arch>.cdx.json. Unset: the bundle says
#                       it holds no SBOM. It never holds an empty one.
#
# Nothing here is signed. SHA256SUMS detects a damaged copy, not a replaced one.
set -euo pipefail

usage() {
    echo "usage: build-bundle.sh <version> <amd64-image-ref> <arm64-image-ref> <out-dir>" >&2
    exit 2
}
fail() {
    echo "build-bundle: $*" >&2
    exit 1
}

[ "$#" -eq 4 ] || usage
VERSION="$1"
REF_AMD64="$2"
REF_ARM64="$3"
OUT="$4"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "the version must be MAJOR.MINOR.PATCH, without a leading v"
[ "$REF_AMD64" != "$REF_ARM64" ] || fail "the two image references are the same; each architecture has its own image"

RUNTIME="${CONTAINER_RUNTIME:-docker}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH="$(git -C "$REPO" log -1 --format=%ct 2> /dev/null || echo 0)"
fi
export SOURCE_DATE_EPOCH

# Each image is what its argument says, or nothing is written.
for pair in "amd64 $REF_AMD64" "arm64 $REF_ARM64"; do
    arch="${pair%% *}"
    ref="${pair#* }"
    found="$("$RUNTIME" image inspect --format '{{.Os}}/{{.Architecture}}' "$ref" 2> /dev/null)" \
        || fail "no local image $ref; build or load it first (this script pulls nothing)"
    [ "$found" = "linux/$arch" ] || fail "$ref is $found, not linux/$arch"
done

NAME="scanent-$VERSION-airgap"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
TREE="$OUT/$NAME"
[ ! -e "$TREE" ] || fail "$TREE already exists; remove it or choose another directory"
[ ! -e "$TREE.tar" ] || fail "$TREE.tar already exists; remove it or choose another directory"
mkdir -p "$TREE/images" "$TREE/deploy/helm" "$TREE/docs" "$TREE/sbom"

printf '%s\n' "$VERSION" > "$TREE/VERSION"
cp "$REPO/LICENSE" "$REPO/NOTICE" "$TREE/"
cp "$HERE/load.sh" "$HERE/verify.sh" "$TREE/"
cp "$HERE/README.md" "$TREE/README.md"
chmod 0755 "$TREE/load.sh" "$TREE/verify.sh"
cp "$REPO/deploy/compose.yaml" "$REPO/deploy/compose.egress.yaml" "$TREE/deploy/"
cp -R "$REPO/deploy/examples" "$TREE/examples"
for doc in quick-start.md deployment.md scanner.md access.md; do
    cp "$REPO/docs/$doc" "$TREE/docs/$doc"
done

# The chart as the archive `helm install` takes: the chart directory, named scanent/.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
    -C "$REPO/deploy/helm" -cf - scanent | gzip -n > "$TREE/deploy/helm/scanent-$VERSION.tgz"

# One archive per architecture: `docker load`, `podman load`, `nerdctl load`
# and `ctr images import` all read it with no registry. IMAGES tells load.sh
# which reference each archive holds.
: > "$TREE/images/IMAGES"
for pair in "amd64 $REF_AMD64" "arm64 $REF_ARM64"; do
    arch="${pair%% *}"
    ref="${pair#* }"
    file="images/scanent-$VERSION-linux-$arch.tar"
    "$RUNTIME" save -o "$TREE/$file" "$ref"
    [ -s "$TREE/$file" ] || fail "$RUNTIME save wrote nothing for $ref"
    printf '%s %s %s\n' "$arch" "$file" "$ref" >> "$TREE/images/IMAGES"
done

if [ -n "${SCANENT_SBOM_CMD:-}" ]; then
    for pair in "amd64 $REF_AMD64" "arm64 $REF_ARM64"; do
        arch="${pair%% *}"
        ref="${pair#* }"
        # shellcheck disable=SC2086 # the command and its own arguments, split on purpose
        $SCANENT_SBOM_CMD "$ref" > "$TREE/sbom/$arch.cdx.json" || fail "the SBOM command failed for $ref"
        [ -s "$TREE/sbom/$arch.cdx.json" ] || fail "the SBOM command printed nothing for $ref; an empty SBOM is not stored"
    done
else
    printf 'No SBOM in this bundle. Phase 4 adds one.\n' > "$TREE/sbom/README.txt"
fi

# Every file but the list itself, sorted by path.
(
    cd "$TREE"
    find . -type f ! -name SHA256SUMS | LC_ALL=C sort | sed 's|^\./||' | while IFS= read -r f; do
        sha256sum "$f"
    done > SHA256SUMS
)

tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
    -C "$OUT" -cf "$TREE.tar" "$NAME"

echo "bundle: $TREE.tar"
echo "sha256: $(sha256sum "$TREE.tar" | cut -d' ' -f1)"
