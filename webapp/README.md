# Lockstep web app

This directory is a standalone static Progressive Web App. It is not packaged in the Spring Boot API JAR.

## Configuration

`config.js` supplies the API origin at runtime:

```javascript
globalThis.LOCKSTEP_CONFIG = Object.freeze({
    apiBaseUrl: "http://localhost:8080"
});
```

For a production static host, replace that value with the HTTPS origin of the separately deployed API. Add the frontend's exact origin to the API's `ALLOWED_ORIGINS` value and to the Google OAuth client's Authorized JavaScript origins.

The current PWA uses root-relative asset and service-worker URLs, so host it at the origin root. If a reverse proxy publishes it under a path such as `/lockstep`, that proxy must also map the app's root-relative assets and service worker correctly; a dedicated hostname is simpler and less error-prone.

## Local static hosting

Serve this directory at `http://localhost:5173` with any static HTTP server. For example, when Python is installed:

```powershell
python -m http.server 5173 --directory webapp
```

Start the API separately with `./run-local.ps1`.

## Container deployment

Build from the repository root using the `webapp` directory as the Docker context:

```powershell
docker build -t lockstep-webapp webapp
docker run --rm -p 5173:8080 --env-file .env lockstep-webapp
```

The root `.env` must contain `LOCKSTEP_API_BASE_URL=http://localhost:8080` for this command. Alternatively, replace `--env-file .env` with `-e LOCKSTEP_API_BASE_URL=http://localhost:8080`.

Set `LOCKSTEP_API_BASE_URL` to the production API origin when deploying the container. The startup script renders `config.js`; the frontend image does not need to be rebuilt when only the API origin changes. It also configures Nginx to listen on the platform-provided `PORT`, defaulting to `8080` for local containers and Cloud Run.
