#!/bin/sh
set -e

# repo clean test
if [ -n "$(git status --porcelain)" ]; then
    echo "Error: Working directory is not clean. Please commit or stash changes."
    exit 1
fi

# lint & build
echo "Running lint..."
./pixiw run lint
echo "Running build..."
./pixiw run build

# bump version in pixi.toml: a.b.c-dev -> a.b.c
RAW_VERSION=$(./pixiw workspace version)
echo "$RAW_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+-dev$' \
|| { echo "Error: Version not in a.b.c-dev format."; exit 1; }
RELEASE_VERSION=$(echo "$RAW_VERSION" | sed 's/-dev//')

echo "Bumping version to release: $RELEASE_VERSION"
./pixiw workspace version set "$RELEASE_VERSION"

# commit 和 annotated tag va.b.c
git add pixi.toml
git commit -m "chore: release v$RELEASE_VERSION"
git tag -a "v$RELEASE_VERSION" -m "version $RELEASE_VERSION"

# bump version in pixi.toml: a.b.c -> a.b.(c+1)-dev
MAJOR=$(echo "$RELEASE_VERSION" | cut -d. -f1)
MINOR=$(echo "$RELEASE_VERSION" | cut -d. -f2)
PATCH=$(echo "$RELEASE_VERSION" | cut -d. -f3)
NEXT_PATCH=$((PATCH + 1))
NEXT_DEV_VERSION="$MAJOR.$MINOR.$NEXT_PATCH-dev"

echo "Bumping version to next dev: $NEXT_DEV_VERSION"
./pixiw workspace version set "$NEXT_DEV_VERSION"

# commit
git add pixi.toml
git commit -m "chore: bump version to $NEXT_DEV_VERSION"

echo "Release process for v$RELEASE_VERSION completed."
