#!/usr/bin/env bash
#
# Build an installable WordPress plugin zip containing only the runtime files,
# laid out under a wlkns-security/ folder so it unzips straight into
# wp-content/plugins/. Used by the release workflow and runnable locally
# via `npm run package`.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SLUG="wlkns-security"
DIST="$ROOT/dist"
STAGE="$DIST/$SLUG"

rm -rf "$DIST"
mkdir -p "$STAGE/includes"

# Runtime plugin files only — no package.json, scripts, .git, CI, etc.
cp wlkns-security.php uninstall.php honeypot.txt README.md CHANGELOG.md "$STAGE/"
cp -R includes/. "$STAGE/includes/"

# Strip macOS cruft that cp may have carried over.
find "$STAGE" -name '.DS_Store' -delete

( cd "$DIST" && zip -rq "$SLUG.zip" "$SLUG" )

echo "Built $DIST/$SLUG.zip"
