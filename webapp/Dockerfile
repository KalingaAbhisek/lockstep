# Minify the app's own scripts (about 30% less to download on a first visit). Top-level names are kept, so
# the page behaves exactly as the source files do; tests/e2e can run against the result (WEBAPP_DIR).
FROM node:22-alpine AS assets
WORKDIR /assets
COPY app.js crypto-store.js image-import.js live-changes.js sw.js index.html privacy.html privacy.css manifest.webmanifest styles.css ./
COPY vendor ./vendor
# Stamp the service worker with a hash of the release's files (before minifying): each release gets its own
# cache, and sw.js changes whenever any app file does, so browsers always install a complete new release.
RUN release="$(cat index.html privacy.html privacy.css manifest.webmanifest styles.css app.js crypto-store.js image-import.js live-changes.js vendor/jsQR.js vendor/qrcode.js vendor/argon2id.js | sha256sum | cut -c1-16)" \
 && sed -i "s/^const RELEASE = \"source\";/const RELEASE = \"$release\";/" sw.js \
 && grep -q "^const RELEASE = \"$release\";" sw.js
RUN for file in app.js crypto-store.js image-import.js live-changes.js sw.js; do npx --yes uglify-js@3.19.3 "$file" --compress --mangle -o "$file"; done

# Only the minified files, for CI: docker build --target minified-files --output type=local,dest=<dir> webapp
FROM scratch AS minified-files
COPY --from=assets /assets/ /

# Current stable nginx line; Dependabot proposes updates (see .github/dependabot.yml).
FROM nginx:1.30-alpine

# Take Alpine's published security fixes now instead of waiting for a new nginx image (the CI image scan
# fails on any HIGH/CRITICAL finding that already has a fix, for example in curl or brotli).
RUN apk upgrade --no-cache

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html privacy.html privacy.css manifest.webmanifest styles.css /usr/share/nginx/html/
COPY --from=assets /assets/app.js /assets/crypto-store.js /assets/image-import.js /assets/live-changes.js /assets/sw.js /usr/share/nginx/html/
COPY icons /usr/share/nginx/html/icons
COPY vendor /usr/share/nginx/html/vendor
COPY config.template.js /opt/lockstep/config.template.js
COPY api-proxy.conf.template /opt/lockstep/api-proxy.conf.template
COPY docker-entrypoint.d/40-lockstep-config.sh /docker-entrypoint.d/40-lockstep-config.sh

RUN chmod +x /docker-entrypoint.d/40-lockstep-config.sh

ENV LOCKSTEP_API_BASE_URL=""
# The Web OAuth client ID. When set, the page skips the /api/v1/config request on startup.
ENV LOCKSTEP_GOOGLE_CLIENT_ID=""
# true: serve the API at /lockstep/api through this container so the web session uses an HttpOnly cookie.
ENV LOCKSTEP_USE_API_PROXY="false"
ENV PORT=8080
EXPOSE 8080
