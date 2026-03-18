#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   GITCODE_TOKEN=xxx ./scripts/openhitls_upstream_push.sh /path/to/openhitls feature/rfc8879-m1-skeleton
#
# Notes:
# - You need network access to gitcode.com and a valid token.
# - This script only automates branch creation and push in your openHiTLS clone.

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <openhitls_local_repo_path> <branch_name>"
  exit 1
fi

OPENHITLS_REPO="$1"
BRANCH="$2"

if [[ ! -d "$OPENHITLS_REPO/.git" ]]; then
  echo "[ERROR] $OPENHITLS_REPO is not a git repository"
  exit 1
fi

cd "$OPENHITLS_REPO"

git fetch --all --prune
git checkout master || git checkout main
git pull --ff-only

git checkout -B "$BRANCH"

echo "[INFO] Branch ready: $BRANCH"
echo "[INFO] Now copy RFC8879 Mx changes, then commit and push:"
echo "  git add ."
echo "  git commit -m 'feat(tls13): RFC8879 cert compression Mx'"
echo "  git push origin $BRANCH"
