#!/bin/sh
set -eu

: "${PORT:=8080}"
: "${LOCKSTEP_USE_API_PROXY:=false}"
: "${LOCKSTEP_GOOGLE_CLIENT_ID:=${GOOGLE_WEB_CLIENT_ID:-}}"

# The settings are written into nginx.conf and config.js, so check them before using them: a stray quote,
# space or newline must stop the container instead of producing broken or unintended configuration.
# The API address must be an https:// origin (plain http:// only for local development hosts), optionally
# with a path; the Google client ID may be empty (the app then asks the API for it).
fail() { echo "lockstep: $1" >&2; exit 1; }
case "$LOCKSTEP_USE_API_PROXY" in true|false) ;; *) fail "LOCKSTEP_USE_API_PROXY must be true or false." ;; esac
api_url_pattern='^(https://[A-Za-z0-9.-]+|http://(localhost|127\.0\.0\.1|host\.docker\.internal))(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$'
# Empty means "this site's own origin" (the app then calls /api on the same host), except with the proxy.
{ [ -z "${LOCKSTEP_API_BASE_URL:-}" ] && [ "$LOCKSTEP_USE_API_PROXY" != "true" ]; } \
  || printf '%s' "${LOCKSTEP_API_BASE_URL:-}" | grep -Eq "$api_url_pattern" \
  || fail "LOCKSTEP_API_BASE_URL must be the API's https:// address (for example https://api.example.com), got '${LOCKSTEP_API_BASE_URL:-}'."
[ -z "${LOCKSTEP_GOOGLE_CLIENT_ID:-}" ] || printf '%s' "$LOCKSTEP_GOOGLE_CLIENT_ID" | grep -Eq '^[A-Za-z0-9._-]{1,200}$' \
  || fail "LOCKSTEP_GOOGLE_CLIENT_ID may contain only letters, digits, '.', '_' and '-'."
export LOCKSTEP_GOOGLE_CLIENT_ID="${LOCKSTEP_GOOGLE_CLIENT_ID:-}"

envsubst '${PORT} ${LOCKSTEP_API_BASE_URL}' \
  < /etc/nginx/conf.d/default.conf \
  > /tmp/lockstep-nginx.conf
mv /tmp/lockstep-nginx.conf /etc/nginx/conf.d/default.conf

# With LOCKSTEP_USE_API_PROXY=true the browser reaches the API through this site (/lockstep/api), so the
# web app keeps its session in an HttpOnly cookie. Otherwise it calls LOCKSTEP_API_BASE_URL directly.
mkdir -p /etc/nginx/lockstep
if [ "$LOCKSTEP_USE_API_PROXY" = "true" ]; then
  envsubst '${LOCKSTEP_API_BASE_URL}' < /opt/lockstep/api-proxy.conf.template > /etc/nginx/lockstep/api-proxy.conf
  LOCKSTEP_CLIENT_API_BASE_URL=/lockstep
else
  : > /etc/nginx/lockstep/api-proxy.conf
  LOCKSTEP_CLIENT_API_BASE_URL="$LOCKSTEP_API_BASE_URL"
fi
export LOCKSTEP_CLIENT_API_BASE_URL

envsubst '${LOCKSTEP_CLIENT_API_BASE_URL} ${LOCKSTEP_GOOGLE_CLIENT_ID}' \
  < /opt/lockstep/config.template.js \
  > /usr/share/nginx/html/config.js
