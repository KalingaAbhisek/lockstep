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

The production container exposes the PWA only below `/lockstep/`. Its assets, manifest, privacy page, and service worker resolve within that base path. The included Nginx configuration redirects `/lockstep` to `/lockstep/`, serves the application there, and returns a blank `404 Not Found` page for `/` and every other path. Configure an upstream reverse proxy to route `https://kalin.ga/lockstep` and its descendants to this frontend service.

## Local hosting

Build and run the same Nginx container used in production, then open `http://localhost:5173/lockstep/`:

```powershell
docker build -t lockstep-webapp webapp
docker run --rm -p 5173:8080 -e LOCKSTEP_API_BASE_URL=http://host.docker.internal:8080 lockstep-webapp
```

The container returns a blank page at `http://localhost:5173/` and for every path outside `/lockstep/`.

Start the API separately with `./run-local.ps1`.

## Container deployment

Build from the repository root using the `webapp` directory as the Docker context:

```powershell
docker build -t lockstep-webapp webapp
docker run --rm -p 5173:8080 --env-file .env lockstep-webapp
```

The root `.env` must contain `LOCKSTEP_API_BASE_URL=http://localhost:8080` for this command. Alternatively, replace `--env-file .env` with `-e LOCKSTEP_API_BASE_URL=http://localhost:8080`.

Set `LOCKSTEP_API_BASE_URL` to the production API origin when deploying the container. The startup script renders `config.js`; the frontend image does not need to be rebuilt when only the API origin changes. It also configures Nginx to listen on the platform-provided `PORT`, defaulting to `8080` for local containers and Cloud Run.
