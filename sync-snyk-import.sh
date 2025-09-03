#!/usr/bin/env bash
set -euo pipefail

# Required env
: "${SNYK_API:=https://api.snyk.io}"          # or https://api.eu.snyk.io / https://api.au.snyk.io
: "${SNYK_TOKEN:?missing}"
: "${SNYK_ORG_ID:?missing}"
: "${SNYK_INTEGRATION_ID:?missing}"
: "${GITHUB_TOKEN:?missing}"
: "${GH_OWNER:?missing}"
BRANCH_REGEX="${BRANCH_REGEX:-^(main|master|release/.*)$}"
DRY_RUN="${DRY_RUN:-false}"

gh_get() {
  curl -sfSL -H "Authorization: Bearer $GITHUB_TOKEN" -H "User-Agent: snyk-sync/1.0" "$@"
}

list_repos() {
  local page=1 per=100
  while :; do
    if ! gh_get "https://api.github.com/orgs/$GH_OWNER/repos?type=all&per_page=$per&page=$page" | jq -r '.[].name' 2>/dev/null; then
      break
    fi
    page=$((page+1))
  done
  # If nothing returned, try user repos
  if [ -z "${repos:-}" ]; then
    page=1
    while :; do
      gh_get "https://api.github.com/users/$GH_OWNER/repos?type=all&per_page=$per&page=$page" | jq -r '.[].name' || break
      page=$((page+1))
    done
  fi
}

list_branches() {
  local repo="$1" page=1 per=100
  while :; do
    gh_get "https://api.github.com/repos/$GH_OWNER/$repo/branches?per_page=$per&page=$page" | jq -r '.[].name' || break
    page=$((page+1))
  done
}

import_branch() {
  local repo="$1" branch="$2"
  local uri="$SNYK_API/v1/org/$SNYK_ORG_ID/integrations/$SNYK_INTEGRATION_ID/import"
  local body
  body=$(jq -nc --arg owner "$GH_OWNER" --arg name "$repo" --arg branch "$branch" \
    '{target:{owner:$owner,name:$name,branch:$branch}}')

  if [ "$DRY_RUN" = "true" ]; then
    echo "DRY-RUN: would import $GH_OWNER/$repo:$branch"
    return 0
  fi

  curl -sfSL -X POST "$uri" \
    -H "Authorization: token $SNYK_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$body" >/dev/null && echo "Imported $GH_OWNER/$repo:$branch" || {
      echo "Import failed for $GH_OWNER/$repo:$branch" >&2
      return 1
    }
}

# Main
command -v jq >/dev/null || { echo "jq is required"; exit 1; }

mapfile -t repos < <(list_repos | sort -u)
for repo in "${repos[@]}"; do
  echo "Repo: $repo"
  mapfile -t branches < <(list_branches "$repo")
  for b in "${branches[@]}"; do
    if [[ "$b" =~ $BRANCH_REGEX ]]; then
      import_branch "$repo" "$b"
    fi
  done
done
