#!/usr/bin/env bash
# Decides whether a commit on main is a release, and if it is, tags it and
# starts the release. Run by .github/workflows/auto-release.yml, from a
# checkout of the commit, with the whole history.
#
#   bash scripts/auto-release.sh
#
#   RELEASE_SHA   required. The commit CI passed on main.
#   GH_REPO       required. owner/name of the repository, for `gh`.
#   GH_TOKEN      read by `gh`. The workflow passes its GITHUB_TOKEN.
#   REMOTE        the remote the tag is read from and pushed to. Default origin.
#
# A release happens when the version in the code changes (owner decision,
# 2026-11-13). In this order, each a stop with a one-line reason and exit 0:
#
#   1. the version is SCANNER_VERSION at the commit, read with the sed the
#      release workflow's Version step uses;
#   2. the tag v<version> already exists on the remote at another commit;
#   3. docs/releases/<version>.md is missing or empty at the commit;
#   4. the commit is no longer the remote's main: a later push has its own run;
#   5. no run of ci.yml on this exact commit, started by a push to main,
#      concluded success.
#
# Then it makes the annotated tag v<version> ("scanent <version>") on the
# commit as github-actions[bot], pushes it, and dispatches release.yml on the
# tag's ref.
#
# A tag that exists already AT THIS COMMIT is a release that was started, or
# one whose tag was pushed and whose dispatch then failed. Checks 3 to 5 still
# apply; then, if release.yml has a run on that tag, whatever its status, it
# stops: a running one is not duplicated, and a failed one is for a person to
# re-run, which keeps the actor github-actions[bot]. If it has none, it
# dispatches release.yml on the tag, and makes no tag.
#
# Anything it cannot find out (no version, a remote or the API that does not
# answer) is a fault, exit 1: a question that could not be asked was not
# answered "no".
set -euo pipefail

stop() {
    echo "nothing to release: $*"
    exit 0
}

fail() {
    echo "auto-release: $*" >&2
    exit 1
}

: "${RELEASE_SHA:?RELEASE_SHA is required}"
: "${GH_REPO:?GH_REPO is required}"
remote="${REMOTE:-origin}"

sha="$(git rev-parse --verify --quiet "${RELEASE_SHA}^{commit}")" || fail "$RELEASE_SHA is not a commit of this checkout"

# 1. The version, as release.yml's Version step reads it, from the commit itself.
surface="$(git show "$sha:packages/scanner/src/scanner-surface.ts")" || fail "packages/scanner/src/scanner-surface.ts could not be read at $sha"
version="$(printf '%s\n' "$surface" | sed -n "s/^export const SCANNER_VERSION = '\([0-9]*\.[0-9]*\.[0-9]*\)';$/\1/p")"
[ -n "$version" ] || fail "SCANNER_VERSION was not found in scanner-surface.ts at $sha"
tag="v$version"

# 2. A version is released once. An annotated tag is read through to its commit
#    (the `^{}` line); a lightweight one names its commit itself.
existing="$(git ls-remote --tags "$remote" "refs/tags/$tag" "refs/tags/$tag^{}")" || fail "the tags of $remote could not be read"
resume=""
if [ -n "$existing" ]; then
    tagged="$(printf '%s\n' "$existing" | awk -v ref="refs/tags/$tag^{}" '$2 == ref { print $1 }')"
    [ -n "$tagged" ] || tagged="$(printf '%s\n' "$existing" | awk -v ref="refs/tags/$tag" '$2 == ref { print $1 }')"
    [ -n "$tagged" ] || fail "the commit the tag $tag names on $remote could not be read"
    [ "$tagged" = "$sha" ] || stop "the tag $tag already exists on $remote, at $tagged"
    resume=1
fi

# 3. The release's own text points at its notes; release.yml refuses a tag without them.
notes="$sha:docs/releases/$version.md"
[ "$(git cat-file -t "$notes" 2> /dev/null || true)" = blob ] && [ "$(git cat-file -s "$notes")" -gt 0 ] \
    || stop "docs/releases/$version.md is missing or empty at $sha"

# 4. Only main's head is tagged: a later push gets its own run, and its own decision.
main="$(git ls-remote "$remote" refs/heads/main)" || fail "the main branch of $remote could not be read"
main="${main%%[[:space:]]*}"
[ -n "$main" ] || fail "$remote has no main branch"
[ "$main" = "$sha" ] || stop "$sha is no longer the head of main ($main is)"

# 5. CI passed on this exact commit, on a push to main. Asked of the API even
#    when the event that started this run said so, so a retry by hand is held
#    to it too.
runs="$(gh api "repos/$GH_REPO/actions/workflows/ci.yml/runs?head_sha=$sha&event=push&branch=main&status=success&per_page=100" \
    --jq '.workflow_runs[] | "\(.head_sha) \(.event) \(.head_branch) \(.conclusion)"')" || fail "the CI runs of $sha could not be read"
printf '%s\n' "$runs" | grep -Fqx "$sha push main success" || stop "no CI run on $sha, pushed to main, concluded success"

if [ -n "$resume" ]; then
    # Any run of release.yml on the tag, of any status, is the release.
    # Every page is read, so a run is never missed for being old.
    started="$(gh api --paginate "repos/$GH_REPO/actions/workflows/release.yml/runs?per_page=100" --jq '.workflow_runs[] | .head_branch')" \
        || fail "the Release runs of $tag could not be read"
    if printf '%s\n' "$started" | grep -Fqx "$tag"; then
        stop "the tag $tag already exists on $remote at $sha, and release.yml has a run on it"
    fi
    gh workflow run release.yml --ref "$tag" --repo "$GH_REPO"
    echo "dispatched release.yml on $tag: the tag exists on $remote at $sha, and release.yml had no run on it"
    exit 0
fi

git -c user.name='github-actions[bot]' -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
    tag -a "$tag" -m "scanent $version" "$sha"
git push "$remote" "refs/tags/$tag"
echo "tagged $sha $tag and pushed it to $remote"

# A tag pushed with GITHUB_TOKEN starts no workflow; a dispatch does. On the
# tag's ref, so the signing identity is release.yml@refs/tags/$tag.
gh workflow run release.yml --ref "$tag" --repo "$GH_REPO"
echo "dispatched release.yml on $tag"
