#!/usr/bin/env bash
# Remove a ladder stack kept with LADDER_KEEP_ON_FAILURE and its scratch dir.
#   scripts/ladder/down.sh <project> <scratch-dir>
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
project="$1"; scratch="$2"
[[ "$scratch" == "$HOME"/.cache/ptpan-ladder.* ]] || { echo "refusing: $scratch is not a ladder scratch directory" >&2; exit 2; }
LADDER_RUN="$scratch" docker compose -p "$project" -f "$root/deploy/ladder/compose.yaml" --profile agents --profile ptpan down -v --remove-orphans
chmod -R u+w "$scratch" 2>/dev/null || true; rm -rf "$scratch"
echo "removed $project and $scratch"
