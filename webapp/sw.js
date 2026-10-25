// RELEASE is replaced at build time (webapp/Dockerfile, build-firebase-hosting.ps1) with a hash of the app's
// files, so every release gets its own cache and this file changes whenever any of them does (which is how
// the browser notices a new release). "source" means an unbuilt copy (local runs, tests).
const RELEASE = "source";
const CACHE_PREFIX = "lockstep-shell-";
const CACHE = `${CACHE_PREFIX}v96-${RELEASE}`;
const BASE_PATH = new URL(self.registration.scope).pathname.replace(/\/$/, "");
const scopedPath = (path = "") => `${BASE_PATH}/${path}`.replace(/\/$/, "/");
const SHELL = ["", "index.html", "privacy.html", "privacy.css", "config.js", "styles.css", "crypto-store.js", "image-import.js", "live-changes.js", "app.js", "vendor/jsQR.js", "vendor/qrcode.js", "vendor/argon2id.js", "manifest.webmanifest"].map(scopedPath);
const SHELL_PATHS = new Set(SHELL);
// Runtime configuration (the API address) always tries the network first.
const NETWORK_FIRST = new Set(["config.js"].map(scopedPath));

self.addEventListener("install", (event) => event.waitUntil(
    // cache: "reload" skips the browser's HTTP cache, so a new release never stores an older file
    // (vendor files are otherwise cached by the browser for a week).
    caches.open(CACHE).then((cache) => cache.addAll(SHELL.map((path) => new Request(path, { cache: "reload" })))).then(() => self.skipWaiting())
));

self.addEventListener("activate", (event) => event.waitUntil(
    caches.keys()
        // Only Lockstep's own older release caches are removed; other caches on this site are left alone.
        .then((keys) => Promise.all(keys.filter((key) => key.startsWith(CACHE_PREFIX) && key !== CACHE).map((key) => caches.delete(key))))
        .then(() => self.clients.claim())
));

function networkFirst(request) {
    return fetch(request).then((response) => {
        if (response.ok) {
            const copy = response.clone();
            caches.open(CACHE).then((cache) => cache.put(request, copy));
        }
        return response;
    }).catch(() => caches.match(request));
}

// A built release serves its files only from its own cache, which the install step filled with one complete,
// matching set; a new release arrives as a new service worker with a new cache, never file by file, so the
// page, scripts and styles always come from the same release. Files outside the release set (icons) and
// unbuilt copies ("source") are served from the cache and refreshed in the background.
function releaseFile(request) {
    // A page address with a query string (for example ?return=close) still opens offline.
    return caches.open(CACHE).then((cache) => cache.match(request, { ignoreSearch: request.mode === "navigate" })).then((cached) => cached || fetch(request));
}

function staleWhileRevalidate(request) {
    return caches.open(CACHE).then((cache) =>
        cache.match(request).then((cached) => {
            const networkFetch = fetch(request).then((response) => {
                if (response.ok) cache.put(request, response.clone());
                return response;
            }).catch(() => cached);
            return cached || networkFetch;
        })
    );
}

self.addEventListener("fetch", (event) => {
    const url = new URL(event.request.url);
    if (!url.protocol.startsWith("http")) return;
    // Only this app's own files are cached. Other origins (Google sign-in, the API) and the same-origin
    // API proxy always go straight to the network.
    if (url.origin !== self.location.origin || !url.pathname.startsWith(`${BASE_PATH}/`)) return;
    if (event.request.method !== "GET" || url.pathname.startsWith("/api/") || url.pathname.startsWith(`${BASE_PATH}/api/`)) return;
    if (NETWORK_FIRST.has(url.pathname)) event.respondWith(networkFirst(event.request));
    else if (RELEASE !== "source" && SHELL_PATHS.has(url.pathname)) event.respondWith(releaseFile(event.request));
    else event.respondWith(staleWhileRevalidate(event.request));
});
