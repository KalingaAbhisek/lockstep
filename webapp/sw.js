const CACHE = "lockstep-shell-v68";
const BASE_PATH = new URL(self.registration.scope).pathname.replace(/\/$/, "");
const scopedPath = (path = "") => `${BASE_PATH}/${path}`.replace(/\/$/, "/");
const SHELL = ["", "index.html", "privacy.html", "config.js", "styles.css", "crypto-store.js", "app.js", "vendor/jsQR.js", "vendor/qrcode.js", "manifest.webmanifest"].map(scopedPath);

self.addEventListener("install", (event) => event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting())
));

self.addEventListener("activate", (event) => event.waitUntil(
    caches.keys()
        .then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
        .then(() => self.clients.claim())
));

self.addEventListener("fetch", (event) => {
    const url = new URL(event.request.url);
    if (!url.protocol.startsWith("http")) return;
    if (event.request.method !== "GET" || url.pathname.startsWith("/api/")) return;
    const isShell = SHELL.includes(url.pathname) || url.pathname === `${BASE_PATH}/`;
    if (isShell) {
        event.respondWith(
            fetch(event.request).then((response) => {
                const copy = response.clone();
                caches.open(CACHE).then((cache) => cache.put(event.request, copy));
                return response;
            }).catch(() => caches.match(event.request))
        );
    } else {
        event.respondWith(
            caches.open(CACHE).then((cache) =>
                cache.match(event.request).then((cached) => {
                    const networkFetch = fetch(event.request).then((response) => {
                        cache.put(event.request, response.clone());
                        return response;
                    }).catch(() => cached);
                    return cached || networkFetch;
                })
            )
        );
    }
});
