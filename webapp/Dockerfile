FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html privacy.html manifest.webmanifest styles.css app.js crypto-store.js sw.js /usr/share/nginx/html/
COPY icons /usr/share/nginx/html/icons
COPY vendor /usr/share/nginx/html/vendor
COPY config.template.js /opt/lockstep/config.template.js
COPY docker-entrypoint.d/40-lockstep-config.sh /docker-entrypoint.d/40-lockstep-config.sh

RUN chmod +x /docker-entrypoint.d/40-lockstep-config.sh

ENV LOCKSTEP_API_BASE_URL=https://lockstep.1309.sh
EXPOSE 80
