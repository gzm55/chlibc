#!/usr/bin/env bash
set -e

if [ -n "$(git status --porcelain -uno)" ]; then
    echo "Error: Working directory is not clean."
    git status -uno
    exit 1
fi

./pixiw run lint
./pixiw run build

if [ -n "$(git status --porcelain -uno)" ]; then
    echo "Error: Working directory is not clean after building."
    git status -uno
    exit 1
fi

DEV_VERSION=$(./pixiw workspace version get)
if [[ ! "$DEV_VERSION" == *-dev ]]; then
    echo "Error: Current version $DEV_VERSION does not have -dev suffix."
    exit 1
fi

RELEASE_VERSION="${DEV_VERSION%-dev}"
echo "Step: Setting release version $RELEASE_VERSION"
./pixiw workspace version set "$RELEASE_VERSION"

git add pixi.toml
git commit -m "chore: release v$RELEASE_VERSION"

# build again for the new hash after setting version
rm -rf build
./pixiw run build

SHA256_X64=$(sha256sum build/clang-x86_64/bin/chlibc | awk '{print $1}')
SHA256_AARCH64=$(sha256sum build/clang-aarch64/bin/chlibc | awk '{print $1}')

TAG_MSG=$(printf "version %s\n\nSHA256 Checksums:\n%s  chlibc-x86_64\n%s  chlibc-aarch64" \
    "$RELEASE_VERSION" "$SHA256_X64" "$SHA256_AARCH64")

git tag -a "v$RELEASE_VERSION" -m "$TAG_MSG"

echo "Step: Reverting to $DEV_VERSION for next bump"
./pixiw workspace version set "$DEV_VERSION"

BUMP_TYPE=${1:-patch}
echo "Step: Bumping $BUMP_TYPE..."
./pixiw workspace version "$BUMP_TYPE"

NEXT_DEV_VERSION=$(./pixiw workspace version get)
git add pixi.toml
git commit -m "chore: bump version to $NEXT_DEV_VERSION"

echo "Release process for v$RELEASE_VERSION finished. Current: $NEXT_DEV_VERSION"
