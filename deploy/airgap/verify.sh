#!/bin/sh
# Checks an unpacked scanent bundle against its SHA256SUMS: every listed file
# has the listed checksum, and what is present is exactly the files listed, so
# an added file fails as a missing or changed one does. Anything that is not a
# regular file or a directory holding one (a symbolic link, an empty directory)
# fails too: the list cannot vouch for it.
#
#   ./verify.sh
#
# It detects a damaged or incomplete copy. It does not detect a replaced one:
# nothing here is signed, and whoever can replace a file can replace the list.
# Obtain the bundle over a channel you trust.
set -eu

cd "$(dirname "$0")"
[ -f SHA256SUMS ] || { echo "verify: no SHA256SUMS here" >&2; exit 1; }
[ -s SHA256SUMS ] || { echo "verify: SHA256SUMS is empty; nothing was verified" >&2; exit 1; }

if command -v sha256sum > /dev/null 2>&1; then
    sha256sum -c SHA256SUMS > /dev/null || { echo "verify: a file does not match its checksum" >&2; exit 1; }
elif command -v shasum > /dev/null 2>&1; then
    shasum -a 256 -c SHA256SUMS > /dev/null || { echo "verify: a file does not match its checksum" >&2; exit 1; }
else
    echo "verify: neither sha256sum nor shasum is available; nothing was verified" >&2
    exit 1
fi

# Everything that is not a directory must be a regular file; the comparison below then covers all of it.
odd="$(find . ! -type d ! -type f | head -n 1)"
if [ -n "$odd" ]; then
    echo "verify: something here is neither a file nor a directory (a link, a device); the bundle holds only files" >&2
    exit 1
fi
if [ -n "$(find . -mindepth 1 -type d -empty | head -n 1)" ]; then
    echo "verify: an empty directory is here that the bundle does not hold" >&2
    exit 1
fi

listed="$(sed 's/^[0-9a-f]*[ *]*//' SHA256SUMS | LC_ALL=C sort)"
present="$(find . ! -type d ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort)"
if [ "$listed" != "$present" ]; then
    echo "verify: the files here are not the files SHA256SUMS lists" >&2
    exit 1
fi

echo "verify: $(printf '%s\n' "$listed" | wc -l | tr -d ' ') files match SHA256SUMS"
