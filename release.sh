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
if [[ ! "$DEV_VERSION" == *.dev ]]; then
    echo "Error: Current version $DEV_VERSION does not have .dev suffix."
    exit 1
fi

RELEASE_VERSION="${DEV_VERSION%.dev}"
echo "Step: Setting release version $RELEASE_VERSION"
./pixiw workspace version set "$RELEASE_VERSION"

# bump the release version in conda recipe, but clear the archive hash
sed -i.bak "s/\(release_version: \)\"[^\"]*\"/\1\"$RELEASE_VERSION\"/" conda/recipe.yaml
sed -i.bak "s/\(release_hash: \)\"[^\"]*\"/\1\"\"/" conda/recipe.yaml

git add pixi.toml conda/recipe.yaml
git commit -m "chore: release v$RELEASE_VERSION"

# build again for the new hash after setting version
rm -rf build
./pixiw run build

ARCH_MAP="x86_64:build/clang-x86_64 aarch64:build/clang-aarch64 ppc64le:build/gcc-powerpc64le"
CHECKSUMS_TEXT=""

for cfg in $ARCH_MAP; do
    arch=${cfg%%:*}
    path=${cfg#*:}
    hash=$(sha256sum "$path/bin/chlibc" | awk '{print $1}')
    CHECKSUMS_TEXT="${CHECKSUMS_TEXT}${hash}  chlibc-${arch}\n"
done

git tag "v$RELEASE_VERSION"
SOURCE_HASH=$(printf "%b" "$CHECKSUMS_TEXT" \
    | ./archive.sh - checksum.txt \
    | sha256sum \
    | awk '{print $1}')
CHECKSUMS_TEXT="${CHECKSUMS_TEXT}${SOURCE_HASH}  source.tar.gz\n"

TAG_MSG=$(printf "version %s\n\nSHA256 Checksums:\n%b" "$RELEASE_VERSION" "$CHECKSUMS_TEXT")

git tag -a -f "v$RELEASE_VERSION" -m "$TAG_MSG"

echo "Step: Reverting to $DEV_VERSION for next bump"
./pixiw workspace version set "$DEV_VERSION"

BUMP_TYPE=${1:-patch}
echo "Step: Bumping $BUMP_TYPE..."
./pixiw workspace version "$BUMP_TYPE"

NEXT_DEV_VERSION=$(./pixiw workspace version get)

# update the archive hash in conda recipe
sed -i.bak "s/\(release_hash: \)\"\"/\1\"$SOURCE_HASH\"/" conda/recipe.yaml

git add pixi.toml conda/recipe.yaml
git commit -m "chore: bump version to $NEXT_DEV_VERSION"

echo "Release process for v$RELEASE_VERSION finished. Current: $NEXT_DEV_VERSION"
