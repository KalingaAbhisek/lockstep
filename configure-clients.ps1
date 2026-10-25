# Generates public configuration only. Never copies .env or server credentials to clients.
param(
    [string]$EnvFile = (Join-Path $PSScriptRoot '.env'),
    [string]$OutputRoot = $PSScriptRoot
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'tools/Load-Env.ps1')
$fileSettings = Read-LockstepEnv -Path $EnvFile
$OutputRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputRoot)

function Get-Setting([string]$Name, [string]$Fallback = '') {
    $value = Get-LockstepSetting -Values $fileSettings -Name $Name
    if ([string]::IsNullOrWhiteSpace($value)) { return $Fallback }
    return $value.Trim()
}
function Assert-Address([string]$Value, [string]$Name) {
    if ($Value -notmatch '^(https://[A-Za-z0-9.-]+|http://(localhost|127\.0\.0\.1))(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$') {
        throw "$Name must be an HTTPS address (HTTP is allowed for localhost)."
    }
    $parsed = [Uri]$Value
    if (-not $parsed.IsAbsoluteUri) { throw "$Name must be an absolute address." }
}
$api = (Get-Setting 'LOCKSTEP_API_BASE_URL').TrimEnd('/')
$web = (Get-Setting 'LOCKSTEP_WEB_BASE_URL').TrimEnd('/')
$webId = Get-Setting 'GOOGLE_WEB_CLIENT_ID'
$extensionId = Get-Setting 'GOOGLE_EXTENSION_CLIENT_ID'
Assert-Address $api 'LOCKSTEP_API_BASE_URL'
Assert-Address $web 'LOCKSTEP_WEB_BASE_URL'
foreach ($id in @($webId, $extensionId)) {
    if ($id -and $id -notmatch '^[A-Za-z0-9._-]{1,200}$') { throw 'Invalid Google OAuth client ID.' }
}
$proxy = Get-Setting 'LOCKSTEP_USE_API_PROXY' 'false'
if ($proxy -notin @('true', 'false')) { throw 'LOCKSTEP_USE_API_PROXY must be true or false.' }
$clientApi = if ($proxy -eq 'true') { '/lockstep' } else { $api }
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'extension/manifest.template.json') -Raw | ConvertFrom-Json
$origin = ([Uri]$api).GetLeftPart([UriPartial]::Authority)
$manifest.host_permissions = @("$origin/*")
$manifest.content_security_policy.extension_pages = $manifest.content_security_policy.extension_pages.Replace('LOCKSTEP_API_ORIGIN', $origin)
$webConfig = 'globalThis.LOCKSTEP_CONFIG = Object.freeze(' + (@{apiBaseUrl=$clientApi; googleClientId=$webId} | ConvertTo-Json -Compress) + ");`n"
# Retain the optional connection prewarm from the web template.
$template = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'webapp/config.template.js') -Raw
$webConfig += $template.Substring($template.IndexOf('// Open the connection'))
$extensionConfig = 'globalThis.AUTHSYNC_CONFIG = Object.freeze(' + (@{apiBaseUrl=$api; webBaseUrl=$web; googleClientId=$extensionId} | ConvertTo-Json -Compress) + ");`n"
$encoding = New-Object Text.UTF8Encoding($false)
foreach ($directory in @('webapp', 'extension')) { New-Item -ItemType Directory -Force (Join-Path $OutputRoot $directory) | Out-Null }
[IO.File]::WriteAllText((Join-Path $OutputRoot 'webapp/config.js'), $webConfig, $encoding)
[IO.File]::WriteAllText((Join-Path $OutputRoot 'extension/config.js'), $extensionConfig, $encoding)
[IO.File]::WriteAllText((Join-Path $OutputRoot 'extension/manifest.json'), ($manifest | ConvertTo-Json -Depth 20), $encoding)
Write-Host 'Generated webapp/config.js, extension/config.js and extension/manifest.json (public settings only).'
