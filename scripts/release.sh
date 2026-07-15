#!/usr/bin/env bash
set -euo pipefail

# Release a semantic version. The tag-triggered GitHub Action builds the
# binaries, uploads them, and creates the release.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

version="${1:-}"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	printf 'usage: %s v1.2.3\n' "$0" >&2
	exit 1
fi

if ! git diff-index --quiet HEAD --; then
	printf 'working tree is not clean; commit or stash changes before releasing\n' >&2
	git status --short >&2
	exit 1
fi

branch="$(git branch --show-current)"
if [[ -z "$branch" ]]; then
	printf 'release must run from a named branch\n' >&2
	exit 1
fi

if git rev-parse "$version" >/dev/null 2>&1; then
	printf 'tag %s already exists locally\n' "$version" >&2
	exit 1
fi

printf 'Running tests...\n'
go test ./...
printf 'Running vet...\n'
go vet ./...

printf 'Creating annotated tag %s...\n' "$version"
git tag -a "$version" -m "$version"

printf 'Pushing %s and %s...\n' "$branch" "$version"
git push origin "$branch" "$version"

printf 'Tag pushed. GitHub Actions will build the binaries and create release %s.\n' "$version"
