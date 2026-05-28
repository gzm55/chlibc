#!/bin/bash

set -eufo pipefail
[ "${DEBUG-}" != true ] || set -x

COMMIT_HASH="${1:-HEAD}"
EXTRA_PATH="${2:-}"

DESCRIBE_ARGS=( describe )
if [[ $COMMIT_HASH == -* ]]; then
  DESCRIBE_ARGS+=( --tags )
  COMMIT_HASH="${COMMIT_HASH#-}"
  COMMIT_HASH="${COMMIT_HASH:-HEAD}"
fi

PREFIX=$(git "${DESCRIBE_ARGS[@]}" -- "$COMMIT_HASH")

PREFIX="chlibc-$PREFIX/"
ARCHIVE_ARGS=(--format=tar --prefix="$PREFIX")

if [[ ${EXTRA_PATH-} ]]; then
  EXTRA_CONTENT="$(cat; echo x)"
  ARCHIVE_ARGS+=("--add-virtual-file=\"$PREFIX$EXTRA_PATH\":${EXTRA_CONTENT%x}")
fi

git archive "${ARCHIVE_ARGS[@]}" "$COMMIT_HASH" \
| "$(dirname -- "$0")"/pixiw run gzip -9nc
