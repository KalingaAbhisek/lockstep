param([switch]$InitializeOnly)

$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot
$envFile = Join-Path $projectRoot ".env"
$wrapper = Join-Path $projectRoot "mvnw.cmd"

if (-not (Test-Path -LiteralPath $envFile)) {
    $initialValues = @(
        "# Local Lockstep configuration. This file is ignored by Git.",
        "GOOGLE_WEB_CLIENT_ID=",
        "GOOGLE_EXTENSION_CLIENT_ID=",
        "ALLOWED_ORIGINS=http://localhost:5173",
        "FIREBASE_PROJECT_ID=",
        "GOOGLE_APPLICATION_CREDENTIALS=",
        "LOCKSTEP_API_BASE_URL=http://localhost:8080"
    )
    [IO.File]::WriteAllLines($envFile, $initialValues)
    Write-Host "Created .env. Add the Google and Firebase settings before starting Lockstep." -ForegroundColor Yellow
}

Get-Content -LiteralPath $envFile |
    Where-Object { $_ -and -not $_.TrimStart().StartsWith("#") } |
    ForEach-Object {
        $variableName, $variableValue = $_ -split "=", 2
        if ($variableName -and $variableValue) {
            $cleanValue = $variableValue.Trim().Trim('"').Trim("'")
            if ($cleanValue) { [Environment]::SetEnvironmentVariable($variableName.Trim(), $cleanValue, "Process") }
        }
    }

if ($InitializeOnly) {
    Write-Host ".env is ready. Encryption keys are generated and retained by each client." -ForegroundColor Green
    exit 0
}

if (-not $env:FIREBASE_PROJECT_ID) { throw "FIREBASE_PROJECT_ID is blank in .env." }
if (-not $env:GOOGLE_APPLICATION_CREDENTIALS) { throw "GOOGLE_APPLICATION_CREDENTIALS is blank in .env." }

if (-not [IO.Path]::IsPathRooted($env:GOOGLE_APPLICATION_CREDENTIALS)) {
    $resolvedCredentialsPath = [IO.Path]::GetFullPath((Join-Path $projectRoot $env:GOOGLE_APPLICATION_CREDENTIALS))
    [Environment]::SetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS", $resolvedCredentialsPath, "Process")
}
if (-not (Test-Path -LiteralPath $env:GOOGLE_APPLICATION_CREDENTIALS -PathType Leaf)) {
    throw "The Firebase service-account file does not exist: $env:GOOGLE_APPLICATION_CREDENTIALS"
}

Push-Location $projectRoot
try { & $wrapper -pl server spring-boot:run }
finally { Pop-Location }
