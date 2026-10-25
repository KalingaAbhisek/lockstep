# Security policy

Lockstep stores authenticator secrets, so security reports are welcome and handled first.

## Reporting a vulnerability

Please report privately, not in a public issue:

1. Open the repository on GitHub, go to **Security → Advisories → Report a vulnerability**
   (GitHub's private vulnerability reporting), and describe the problem, the affected component (API,
   web app, browser extension, deployment files) and how to reproduce it.
2. You should get an acknowledgement within 7 days. Please allow up to 90 days for a fix before
   disclosing details publicly; we will agree a date with you.

Please do not access, change or delete other people's data, and do not run denial-of-service or
volume tests against the production service (`lockstep.1309.sh`, `kalin.ga/lockstep`).

## Scope

In scope: the Spring Boot API (`server/`), the web app (`webapp/`), the Chrome extension (`extension/`),
Firestore rules and indexes, the container images and the GitHub workflows in this repository.

Especially interesting: anything that lets someone read or change another account's vault, recover
secrets or the vault key without the passphrase or recovery key, bypass the recent-Google-sign-in check,
replace a newer wrapped key, or run script in the web app or extension.

Out of scope: findings that need a compromised device or browser profile, social engineering, and
missing best-practice headers without a demonstrated impact.

## Supported versions

Only the latest release of the API, web app and extension receives security fixes.

## Design notes

How the vault is encrypted, what the server can and cannot see, and the threat model are described in
[ARCHITECTURE.md](ARCHITECTURE.md) and [README.md](README.md). Deployment hardening is in
[DEPLOYMENT.md](DEPLOYMENT.md).


## Configuration and secrets

Keep `.env`, environment-specific variants and service-account files out of Git and release artifacts. `.env.example` documents safe placeholders. Local setup and build scripts read `.env`; they generate browser configuration from an explicit allowlist of public values. API/site URLs and OAuth client IDs remain visible in the browser and extension. Service-account credentials, client secrets, access tokens and vault keys must never be included in those outputs. Store runtime user tokens and vault keys through the application's existing protected storage flows, not `.env`.

Edit extension metadata in `extension/manifest.template.json`, then run `./configure-clients.ps1`; generated client configs and the extension manifest are ignored by Git. Production services receive their own runtime environment settings. Supply only public frontend variables to frontend containers, and use an attached service account for the production API. See [DEPLOYMENT.md](DEPLOYMENT.md) for the generated Firebase Hosting config and deployment commands.

Routine synchronization on current servers obtains key metadata and encrypted accounts from the same revision-fenced snapshot. A remotely changed key locks the receiving client before returning ciphertext to its decryption/rendering path. Extension navigation and code-refresh callbacks also check their originating view generation before modifying a newer lock/recovery screen.

File-import cancellation: backup/QR preprocessing is tied to its originating vault view, and late recovery-file reads cannot refill a cleared form or replace a newer selection. Backup-password dialogs accept only one submission at a time; cancelled derivations cannot reset or close a later dialog. Both clients validate supported wrapping algorithms, salt size and bounded integer KDF parameters before starting derivation, including local vault records; valid encryption settings are unchanged.
