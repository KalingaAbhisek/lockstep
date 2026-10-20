#!/bin/sh
set -eu

: "${PORT:=8080}"

envsubst '${PORT}' \
  < /etc/nginx/conf.d/default.conf \
  > /tmp/lockstep-nginx.conf
mv /tmp/lockstep-nginx.conf /etc/nginx/conf.d/default.conf

envsubst '${LOCKSTEP_API_BASE_URL}' \
  < /opt/lockstep/config.template.js \
  > /usr/share/nginx/html/config.js
