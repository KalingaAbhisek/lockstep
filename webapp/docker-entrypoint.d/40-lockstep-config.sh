#!/bin/sh
set -eu

envsubst '${LOCKSTEP_API_BASE_URL}' \
  < /opt/lockstep/config.template.js \
  > /usr/share/nginx/html/config.js
