#!/bin/sh
# Checks an unpacked scanent bundle.
#
#   ./verify.sh [--unsigned | --no-signature | --require-signature]
#
# 1. Checksums. Every file SHA256SUMS lists has the listed checksum, and what
#    is present is exactly the files listed, so an added file fails as a
#    missing or changed one does. Anything that is not a regular file or a
#    directory holding one (a symbolic link, an empty directory) fails too: the
#    list cannot vouch for it. The two files outside the list are the list
#    itself, at the top of the bundle, and the signature over it,
#    signatures/SHA256SUMS.sigstore.json. A file named SHA256SUMS anywhere
#    else is an added file like any other.
# 2. The SBOM. sbom/ holds one non-empty CycloneDX document per image, or the
#    notice that the bundle was built without one. Never both, never neither.
# 3. The signature. A released bundle carries a Sigstore bundle over
#    SHA256SUMS, made by the release workflow with its own identity and no
#    stored key. With `cosign` on the path it is verified against that
#    identity, for the version this bundle names, and a failure fails. With
#    the signature present and no `cosign`, this stops and says so: silence
#    would read as verified. A bundle with NO signature fails as well: taking
#    the signature out is the first thing someone replacing a release bundle
#    would do, so its absence is never accepted without being asked for.
#
#   (no flag)             the bundle must carry a signature, and it must
#                         verify. What a released bundle is checked with.
#   --unsigned            accept a bundle that carries no signature: one you
#                         built yourself with build-bundle.sh. A signature
#                         that IS present is still checked.
#   --no-signature        do not check the signature, present or not; say
#                         that it was not.
#   --require-signature   the same as no flag. Kept so that a command written
#                         for an earlier version means what it meant.
#
#   SCANENT_TRUSTED_ROOT  optional: a Sigstore trusted root file, passed to
#                         cosign as --trusted-root. For a machine where cosign
#                         cannot fetch or has not cached the public root.
#
# Checksums alone detect a damaged or incomplete copy. They do not detect a
# replaced one: whoever can replace a file can replace the list. The signature
# is what ties the list to the release.
set -eu

fail() {
    echo "verify: $*" >&2
    exit 1
}

usage() {
    echo "usage: verify.sh [--unsigned | --no-signature | --require-signature]" >&2
    exit 2
}

mode=default
for a in "$@"; do
    [ "$mode" = default ] || usage
    case "$a" in
        --require-signature) mode=require ;;
        --unsigned) mode=unsigned ;;
        --no-signature) mode=skip ;;
        *) usage ;;
    esac
done

cd "$(dirname "$0")"
SIGNATURE=signatures/SHA256SUMS.sigstore.json
[ -f SHA256SUMS ] || fail "no SHA256SUMS here"
[ -s SHA256SUMS ] || fail "SHA256SUMS is empty; nothing was verified"

if command -v sha256sum > /dev/null 2>&1; then
    sha256sum -c SHA256SUMS > /dev/null || fail "a file does not match its checksum"
elif command -v shasum > /dev/null 2>&1; then
    shasum -a 256 -c SHA256SUMS > /dev/null || fail "a file does not match its checksum"
else
    fail "neither sha256sum nor shasum is available; nothing was verified"
fi

# Everything that is not a directory must be a regular file; the comparison below then covers all of it.
odd="$(find . ! -type d ! -type f | head -n 1)"
[ -z "$odd" ] || fail "something here is neither a file nor a directory (a link, a device); the bundle holds only files"
[ -z "$(find . -mindepth 1 -type d -empty | head -n 1)" ] || fail "an empty directory is here that the bundle does not hold"

listed="$(sed 's/^[0-9a-f]*[ *]*//' SHA256SUMS | LC_ALL=C sort)"
# Only the list at the top is left out: a SHA256SUMS in any directory below is a file the list must name.
present="$(find . ! -type d ! -path ./SHA256SUMS | sed 's|^\./||' | grep -vx "$SIGNATURE" | LC_ALL=C sort)"
[ "$listed" = "$present" ] || fail "the files here are not the files SHA256SUMS lists"

echo "verify: $(printf '%s\n' "$listed" | wc -l | tr -d ' ') files match SHA256SUMS"

# ── the SBOM ──
[ -d sbom ] || fail "the bundle has no sbom directory"
documents="$(find sbom -type f -name '*.cdx.json' | wc -l | tr -d ' ')"
if [ -f sbom/README.txt ]; then
    [ "$documents" -eq 0 ] || fail "sbom/ holds both an SBOM and the notice that there is none"
    [ "$(find sbom -type f | wc -l | tr -d ' ')" -eq 1 ] || fail "sbom/ holds a file that is neither an SBOM nor the notice"
    echo "verify: this bundle was built without an SBOM"
else
    [ -f images/IMAGES ] || fail "images/IMAGES is missing"
    expected=0
    while read -r arch _file _ref; do
        expected=$((expected + 1))
        doc="sbom/$arch.cdx.json"
        [ -s "$doc" ] || fail "the SBOM for $arch is missing or empty"
        if ! grep -q '"bomFormat"' "$doc" || ! grep -q 'CycloneDX' "$doc"; then
            fail "the SBOM for $arch is not a CycloneDX document"
        fi
    done < images/IMAGES
    [ "$expected" -gt 0 ] || fail "images/IMAGES names no image"
    [ "$(find sbom -type f | wc -l | tr -d ' ')" -eq "$expected" ] || fail "sbom/ holds a file that is not the SBOM of one of the images"
    echo "verify: $expected CycloneDX SBOMs, one per image"
fi

# ── the signature ──
if [ ! -e "$SIGNATURE" ]; then
    case "$mode" in
        unsigned | skip)
            echo "verify: this bundle carries no signature. The checksums detect damage, not a replaced bundle"
            exit 0
            ;;
        require) fail "this bundle carries no signature, and --require-signature was given" ;;
    esac
    echo "verify: this bundle carries no signature, so nothing shows it is the one the release made." >&2
    echo "verify: a released bundle is signed. Pass --unsigned only for a bundle you built yourself." >&2
    exit 1
fi
[ -s "$SIGNATURE" ] || fail "the signature file is empty"
if [ "$mode" = skip ]; then
    echo "verify: the signature was NOT checked (--no-signature)"
    exit 0
fi
version="$(cat VERSION)"
case "$version" in
    *[!0-9.]* | "" | .* | *. | *..*) fail "VERSION does not hold a version" ;;
esac
identity="https://github.com/RodnaPamet/scanent/.github/workflows/release.yml@refs/tags/v$version"
issuer="https://token.actions.githubusercontent.com"
if ! command -v cosign > /dev/null 2>&1; then
    echo "verify: this bundle is signed, and cosign is not on the path, so the signature was NOT checked." >&2
    echo "verify: install cosign and run this again, or pass --no-signature to accept the checksums alone." >&2
    exit 1
fi
# The Sigstore bundle carries the certificate and the transparency-log entry,
# so the check needs no network beyond the public root; SCANENT_TRUSTED_ROOT
# supplies that from a file. cosign's own words are kept and shown on a
# failure: "does not verify" and "this cosign cannot read the bundle" need
# different actions, and only cosign knows which it was.
set -- --bundle "$SIGNATURE" --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" SHA256SUMS
if [ -n "${SCANENT_TRUSTED_ROOT:-}" ]; then
    set -- --trusted-root "$SCANENT_TRUSTED_ROOT" "$@"
fi
if ! said="$(cosign verify-blob "$@" 2>&1)"; then
    [ -z "$said" ] || printf '%s\n' "$said" | sed 's/^/verify: cosign: /' >&2
    fail "the signature over SHA256SUMS does not verify for $identity"
fi
echo "verify: SHA256SUMS is signed by $identity"
