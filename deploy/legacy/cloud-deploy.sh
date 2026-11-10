#!/usr/bin/env bash
# Pre-flight check before deploying. Verifies the repository is in a
# deployable state and prints the remaining manual steps.
set -euo pipefail

cd "$(dirname "$0")"

fail=0
say() { printf '%s\n' "$*"; }
check() { if eval "$2" >/dev/null 2>&1; then say "  [ok]   $1"; else say "  [FAIL] $1"; fail=1; fi; }

say "HoneySentinel — deployment pre-flight"
say

say "Repository:"
check "git repository initialised" "[ -d .git ]"
check "a remote named 'origin' exists" "git remote get-url origin"
check "no uncommitted changes" "[ -z \"\$(git status --porcelain)\" ]"
check ".env is not tracked by git" "! git ls-files --error-unmatch .env"

say
say "Required files:"
for f in render.yaml vercel.json backend/requirements.txt honeypot/requirements.txt package.json; do
    check "$f present" "[ -f $f ]"
done

say
say "Build:"
check "frontend dependencies installed" "[ -d node_modules ]"
if [ -d node_modules ]; then
    check "frontend builds" "npm run build"
    check "frontend lints clean" "npm run lint"
fi

say
if [ "$fail" -ne 0 ]; then
    say "Pre-flight FAILED. Fix the items above before deploying."
    exit 1
fi

say "Pre-flight passed."
say
say "Remaining manual steps:"
say "  1. Render : New + -> Blueprint -> select this repository."
say "             Fill in CORS_ORIGINS; copy the generated"
say "             HONEYPOT_INGEST_TOKEN out of the dashboard."
say "  2. Vercel : New Project -> import this repository."
say "             Set VITE_API_URL to your Render API URL + /api/v1."
say "  3. Backend: add the Vercel origin to CORS_ORIGINS."
say "  4. Engine : on your own VPS, set BACKEND_API_URL and the same"
say "             HONEYPOT_INGEST_TOKEN, then:"
say "               docker compose up -d --build honeypot"
say
say "Full walkthrough: DEPLOY.md"
