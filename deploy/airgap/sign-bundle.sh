#!/usr/bin/env bash
# Signs a bundle that build-bundle.sh made without a signature, and makes the
# archive again with the signature inside it.
#
#   deploy/airgap/sign-bundle.sh <scanent-<version>-airgap.tar> <out-dir>
#
#   SCANENT_SIGN_CMD    required. Run once with two more arguments: the file
#                       to write the signature to, then SHA256SUMS. The
#                       release passes `cosign sign-blob --yes --bundle`.
#   SOURCE_DATE_EPOCH   the modification time written into the archive.
#                       Default: the one the unsigned archive was made with.
#
# It exists so that the release builds and tests the bundle in a job that
# cannot ask for the signing identity, and signs it in a job that runs for a
# pushed tag only and does nothing else. The tree is checked with its own
# verify.sh before it is signed: a list that does not match its files is not
# signed. This script holds no key and signs nothing itself.
#
# It writes <out-dir>/scanent-<version>-airgap/ and
# <out-dir>/scanent-<version>-airgap.tar, the same two paths build-bundle.sh
# writes, and the same bytes build-bundle.sh writes when it is given the
# signing command itself.
set -euo pipefail

fail() {
    echo "sign-bundle: $*" >&2
    exit 1
}

[ "$#" -eq 2 ] || { echo "usage: sign-bundle.sh <scanent-<version>-airgap.tar> <out-dir>" >&2; exit 2; }
IN="$1"
OUT="$2"
[ -n "${SCANENT_SIGN_CMD:-}" ] || fail "SCANENT_SIGN_CMD is not set; there is nothing to sign with"
[ -f "$IN" ] || fail "no archive at $IN"

# One top-level directory, named as build-bundle.sh names it, and nothing beside it.
tops="$(tar -tf "$IN" | sed 's|/.*||' | LC_ALL=C sort -u)"
NAME="$tops"
[[ "$NAME" =~ ^scanent-[0-9]+\.[0-9]+\.[0-9]+-airgap$ ]] || fail "the archive does not hold one scanent-<version>-airgap directory"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
TREE="$OUT/$NAME"
[ ! -e "$TREE" ] || fail "$TREE already exists; remove it or choose another directory"
[ ! -e "$TREE.tar" ] || fail "$TREE.tar already exists; remove it or choose another directory"

tar -xf "$IN" -C "$OUT"
[ ! -e "$TREE/signatures" ] || fail "the bundle already carries a signature; it is not signed twice"
"$TREE/verify.sh" --unsigned > /dev/null || fail "the bundle does not pass its own check; it is not signed"

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH="$(stat -c %Y "$TREE/VERSION")"
fi

mkdir -p "$TREE/signatures"
# shellcheck disable=SC2086 # the command and its own arguments, split on purpose
$SCANENT_SIGN_CMD "$TREE/signatures/SHA256SUMS.sigstore.json" "$TREE/SHA256SUMS" || fail "the signing command failed"
[ -s "$TREE/signatures/SHA256SUMS.sigstore.json" ] || fail "the signing command wrote no signature; an empty one is not stored"
chmod 0644 "$TREE/signatures/SHA256SUMS.sigstore.json"

tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
    -C "$OUT" -cf "$TREE.tar" "$NAME"

echo "bundle: $TREE.tar"
echo "sha256: $(sha256sum "$TREE.tar" | cut -d' ' -f1)"
