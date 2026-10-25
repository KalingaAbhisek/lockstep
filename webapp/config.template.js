globalThis.LOCKSTEP_CONFIG = Object.freeze({
    apiBaseUrl: "${LOCKSTEP_CLIENT_API_BASE_URL}",
    googleClientId: "${LOCKSTEP_GOOGLE_CLIENT_ID}"
});

// Open the connection to a separate API origin while the page is still loading.
(() => {
    try {
        const api = new URL(globalThis.LOCKSTEP_CONFIG.apiBaseUrl, location.href);
        if (api.origin === location.origin) return;
        const link = document.createElement("link");
        link.rel = "preconnect"; link.href = api.origin; link.crossOrigin = "anonymous";
        document.head.append(link);
    } catch { /* optional optimisation */ }
})();
