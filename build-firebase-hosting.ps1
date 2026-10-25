# Builds the static web app for Firebase Hosting into dist\firebase-hosting.
# Usage (API on its own origin):
#         .\build-firebase-hosting.ps1 -ApiBaseUrl https://lockstep.1309.sh -GoogleClientId <web OAuth client ID>
#         firebase deploy --only hosting --config firebase.runtime.json
# Usage (API served through Firebase Hosting at /lockstep/api, so the web session is an HttpOnly cookie):
#         .\build-firebase-hosting.ps1 -CloudRunService <API service name> -CloudRunRegion us-east1 -GoogleClientId <id>
#         firebase deploy --only hosting --config firebase.proxy.json
# The app is published below /lockstep/, matching the Nginx container. Firebase Hosting compresses
# responses (gzip/Brotli), serves them from its CDN and never has a cold start.
param(
    # The API origin the browser calls directly. Not used with -CloudRunService.
    [string]$ApiBaseUrl = "",
    # Optional. When given, the page does not need the /api/v1/config request on startup.
    [string]$GoogleClientId = "",
    # Optional. The Cloud Run API service to serve at /lockstep/api through Firebase Hosting.
    [string]$CloudRunService = "",
    [string]$CloudRunRegion = "us-east1",
    # The app's scripts are minified with uglify-js when Node.js (npx) is installed; this keeps them as they are.
    [switch]$SkipMinify
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot 'tools/Load-Env.ps1')
$fileSettings = @{}
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.env')) {
    $fileSettings = Read-LockstepEnv -Path (Join-Path $PSScriptRoot '.env')
}
if (-not $PSBoundParameters.ContainsKey('ApiBaseUrl')) { $ApiBaseUrl = Get-LockstepSetting $fileSettings 'LOCKSTEP_API_BASE_URL' }
if (-not $PSBoundParameters.ContainsKey('GoogleClientId')) { $GoogleClientId = Get-LockstepSetting $fileSettings 'GOOGLE_WEB_CLIENT_ID' }
if (-not $PSBoundParameters.ContainsKey('CloudRunService')) { $CloudRunService = Get-LockstepSetting $fileSettings 'LOCKSTEP_CLOUD_RUN_SERVICE' }
if (-not $PSBoundParameters.ContainsKey('CloudRunRegion')) { $CloudRunRegion = Get-LockstepSetting $fileSettings 'LOCKSTEP_CLOUD_RUN_REGION' 'us-east1' }
$useProxy = $CloudRunService.Trim() -ne ""
if (-not $useProxy -and $ApiBaseUrl.Trim() -eq "") { throw "Pass -ApiBaseUrl, or -CloudRunService to serve the API through Firebase Hosting." }
# Through the rewrite the API is same-origin, which also switches the web app to the HttpOnly cookie session.
$clientApiBaseUrl = if ($useProxy) { "/lockstep" } else { $ApiBaseUrl.TrimEnd("/") }
# Both values are written into config.js: refuse anything that is not a plain address or client ID.
if (-not $useProxy -and $clientApiBaseUrl -notmatch '^(https://[A-Za-z0-9.-]+|http://(localhost|127\.0\.0\.1))(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$') {
    throw "-ApiBaseUrl must be the API's https:// address (for example https://api.example.com)."
}
if ($GoogleClientId.Trim() -ne "" -and $GoogleClientId.Trim() -notmatch '^[A-Za-z0-9._-]{1,200}$') {
    throw "-GoogleClientId may contain only letters, digits, '.', '_' and '-'."
}
if ($CloudRunService.Trim() -ne "" -and $CloudRunService.Trim() -notmatch '^[a-z][a-z0-9-]{0,62}$') { throw "-CloudRunService is not a valid Cloud Run service name." }
if ($CloudRunRegion -notmatch '^[a-z0-9-]{1,40}$') { throw "-CloudRunRegion is not a valid region name." }
$root = $PSScriptRoot
$source = Join-Path $root "webapp"
$output = Join-Path $root "dist\firebase-hosting"
$app = Join-Path $output "lockstep"

if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output -Recurse -Force }
New-Item -ItemType Directory -Force $app | Out-Null

foreach ($file in @("index.html", "privacy.html", "privacy.css", "manifest.webmanifest", "styles.css", "app.js", "crypto-store.js", "image-import.js", "live-changes.js", "sw.js")) {
    Copy-Item -LiteralPath (Join-Path $source $file) -Destination $app
}
# Stamp the service worker with a hash of the release's files (as webapp/Dockerfile does): each release gets
# its own cache, and sw.js changes whenever any app file does, so browsers install a complete new release.
$releaseFiles = @("index.html", "privacy.html", "privacy.css", "manifest.webmanifest", "styles.css", "app.js", "crypto-store.js", "image-import.js", "live-changes.js", "vendor\jsQR.js", "vendor\qrcode.js", "vendor\argon2id.js")
$hasher = [Security.Cryptography.SHA256]::Create()
$stream = New-Object IO.MemoryStream
foreach ($file in $releaseFiles) { $bytes = [IO.File]::ReadAllBytes((Join-Path $source $file)); $stream.Write($bytes, 0, $bytes.Length) }
$release = (($hasher.ComputeHash($stream.ToArray()) | ForEach-Object { $_.ToString("x2") }) -join "").Substring(0, 16)
$swPath = Join-Path $app "sw.js"
$sw = [IO.File]::ReadAllText($swPath)
if (-not $sw.Contains('const RELEASE = "source";')) { throw "sw.js no longer contains the RELEASE placeholder." }
[IO.File]::WriteAllText($swPath, $sw.Replace('const RELEASE = "source";', "const RELEASE = `"$release`";"))
# Same minification as the container image (top-level names kept). Without Node.js the files stay unminified.
if (-not $SkipMinify -and (Get-Command npx -ErrorAction SilentlyContinue)) {
    foreach ($file in @("app.js", "crypto-store.js", "image-import.js", "live-changes.js", "sw.js")) {
        $target = Join-Path $app $file
        # sw.js is minified from the stamped copy; the others from the source files.
        $minifyInput = if ($file -eq "sw.js") { $target } else { Join-Path $source $file }
        & npx --yes uglify-js@3.19.3 $minifyInput --compress --mangle -o $target
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Could not minify $file; publishing it unminified."
            # The stamped sw.js is already in place; the other files are copied again from the source.
            if ($file -ne "sw.js") { Copy-Item -LiteralPath (Join-Path $source $file) -Destination $app -Force }
        }
    }
} elseif (-not $SkipMinify) {
    Write-Warning "Node.js (npx) not found: publishing the scripts unminified."
}
Copy-Item -LiteralPath (Join-Path $source "icons") -Destination $app -Recurse
Copy-Item -LiteralPath (Join-Path $source "vendor") -Destination $app -Recurse

$config = (Get-Content -LiteralPath (Join-Path $source "config.template.js") -Raw).Replace('${LOCKSTEP_CLIENT_API_BASE_URL}', $clientApiBaseUrl).Replace('${LOCKSTEP_GOOGLE_CLIENT_ID}', $GoogleClientId.Trim())
[IO.File]::WriteAllText((Join-Path $app "config.js"), $config)

# Paths outside /lockstep/ show a blank page, like the Nginx container.
[IO.File]::WriteAllText((Join-Path $output "404.html"), "<!doctype html><title></title>")

if ($useProxy) {
    # firebase.proxy.json = firebase.json plus a rewrite of /lockstep/api/** to the Cloud Run API. The API
    # serves the same routes under /lockstep/api (PUBLIC_PATH_PREFIX) and names the session cookie
    # "__session", the only cookie Firebase Hosting forwards.
    $firebase = Get-Content -LiteralPath (Join-Path $root "firebase.json") -Raw | ConvertFrom-Json
    $rewrite = [pscustomobject]@{ source = "/lockstep/api/**"; run = [pscustomobject]@{ serviceId = $CloudRunService.Trim(); region = $CloudRunRegion.Trim() } }
    $firebase.hosting | Add-Member -NotePropertyName rewrites -NotePropertyValue @($rewrite) -Force
    [IO.File]::WriteAllText((Join-Path $root "firebase.proxy.json"), ($firebase | ConvertTo-Json -Depth 20))
    Write-Host "Built $output. Deploy with: firebase deploy --only hosting --config firebase.proxy.json" -ForegroundColor Green
} else {
    # Generate public headers from the selected API; never copy .env into hosting output.
    $apiOrigin = ([Uri]$ApiBaseUrl).GetLeftPart([UriPartial]::Authority)
    $firebase = Get-Content -LiteralPath (Join-Path $root 'firebase.json') -Raw | ConvertFrom-Json
    foreach ($group in $firebase.hosting.headers) {
        foreach ($header in $group.headers) {
            if ($header.key -eq 'Content-Security-Policy') {
                $header.value = $header.value.Replace("connect-src 'self'", "connect-src 'self' $apiOrigin")
            }
            if ($header.key -like 'Content-Security-Policy*') {
                $header.value = $header.value.Replace('/lockstep/api/v1/csp-report', "$clientApiBaseUrl/api/v1/csp-report")
            }
        }
    }
    [IO.File]::WriteAllText((Join-Path $root 'firebase.runtime.json'), ($firebase | ConvertTo-Json -Depth 20))
    Write-Host "Built $output. Deploy with: firebase deploy --only hosting --config firebase.runtime.json" -ForegroundColor Green
}
