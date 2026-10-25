param([switch]$InitializeOnly)

$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot
$envFile = Join-Path $projectRoot ".env"
$wrapper = Join-Path $projectRoot "mvnw.cmd"

if (-not (Test-Path -LiteralPath $envFile)) {
    Copy-Item -LiteralPath (Join-Path $projectRoot ".env.example") -Destination $envFile
    Write-Host "Created .env. Add the Google and Firebase settings before starting Lockstep." -ForegroundColor Yellow
}

. (Join-Path $projectRoot "tools/Load-Env.ps1")
Import-LockstepEnv -Path $envFile
& (Join-Path $projectRoot "configure-clients.ps1") -EnvFile $envFile

if ($InitializeOnly) {
    Write-Host ".env is ready. Encryption keys are generated and retained by each client." -ForegroundColor Green
    exit 0
}

if (-not $env:FIREBASE_PROJECT_ID) { throw "FIREBASE_PROJECT_ID is blank in .env." }

if ($env:GOOGLE_APPLICATION_CREDENTIALS) {
    # Optional service-account key file (kept for existing setups).
    if (-not [IO.Path]::IsPathRooted($env:GOOGLE_APPLICATION_CREDENTIALS)) {
        $resolvedCredentialsPath = [IO.Path]::GetFullPath((Join-Path $projectRoot $env:GOOGLE_APPLICATION_CREDENTIALS))
        [Environment]::SetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS", $resolvedCredentialsPath, "Process")
    }
    if (-not (Test-Path -LiteralPath $env:GOOGLE_APPLICATION_CREDENTIALS -PathType Leaf)) {
        throw "The Firebase service-account file does not exist: $env:GOOGLE_APPLICATION_CREDENTIALS"
    }
} else {
    # Recommended: no key file. The API uses your own Google login (Application Default Credentials).
    # Run once:  gcloud auth application-default login
    Write-Host "Using Application Default Credentials (gcloud auth application-default login)." -ForegroundColor Cyan
}

Push-Location $projectRoot
try { & $wrapper -pl server spring-boot:run }
finally { Pop-Location }
