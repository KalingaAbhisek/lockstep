$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$work = Join-Path ([IO.Path]::GetTempPath()) ('lockstep-env-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $work | Out-Null
$names = @('LOCKSTEP_API_BASE_URL','LOCKSTEP_WEB_BASE_URL','GOOGLE_WEB_CLIENT_ID','GOOGLE_EXTENSION_CLIENT_ID','LOCKSTEP_USE_API_PROXY','GOOGLE_APPLICATION_CREDENTIALS','GOOGLE_CLIENT_SECRET')
$saved = @{}
foreach ($name in $names) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}
function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
try {
    $file = Join-Path $work '.env'
    [IO.File]::WriteAllText($file, @'
LOCKSTEP_API_BASE_URL=https://api.example.test/prefix
LOCKSTEP_WEB_BASE_URL=https://app.example.test/lockstep
GOOGLE_WEB_CLIENT_ID=web-test.apps.googleusercontent.com
GOOGLE_EXTENSION_CLIENT_ID=extension-test.apps.googleusercontent.com
GOOGLE_APPLICATION_CREDENTIALS=SECRET_SENTINEL_DO_NOT_SHIP.json
GOOGLE_CLIENT_SECRET='SECRET_SENTINEL_DO_NOT_SHIP$(throw "must never execute")'
'@)
    . (Join-Path $root 'tools/Load-Env.ps1')
    $netDirectory = [Environment]::CurrentDirectory
    $otherDirectory = Join-Path $work 'different-dotnet-directory'
    New-Item -ItemType Directory $otherDirectory | Out-Null
    Push-Location $work
    try {
        [Environment]::CurrentDirectory = $otherDirectory
        Import-LockstepEnv -Path './.env'
        Assert ($env:GOOGLE_WEB_CLIENT_ID -eq 'web-test.apps.googleusercontent.com') 'Relative .env paths must use the PowerShell location, not the .NET working directory.'
    } finally {
        [Environment]::CurrentDirectory = $netDirectory
        Pop-Location
    }
    foreach ($name in $names) { Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue }
    & (Join-Path $root 'configure-clients.ps1') -EnvFile $file -OutputRoot $work
    Assert ($null -eq [Environment]::GetEnvironmentVariable('LOCKSTEP_API_BASE_URL', 'Process')) 'Generation must not turn file settings into sticky process overrides.'
    Assert ($null -eq [Environment]::GetEnvironmentVariable('GOOGLE_CLIENT_SECRET', 'Process')) 'Client generation must not import server secrets into the terminal.'
    $web = Get-Content -LiteralPath (Join-Path $work 'webapp/config.js') -Raw
    $ext = Get-Content -LiteralPath (Join-Path $work 'extension/config.js') -Raw
    $manifestText = Get-Content -LiteralPath (Join-Path $work 'extension/manifest.json') -Raw
    $manifest = $manifestText | ConvertFrom-Json
    Assert (($web + $ext + $manifestText) -notmatch 'SECRET_SENTINEL') 'Server secret leaked to browser output.'
    Assert ($web.Contains('web-test.apps.googleusercontent.com')) 'Web client ID missing.'
    Assert ($ext.Contains('extension-test.apps.googleusercontent.com')) 'Extension client ID missing.'
    Assert ($manifest.host_permissions.Count -eq 1 -and $manifest.host_permissions[0] -eq 'https://api.example.test/*') 'Manifest permissions must use the API origin only.'
    Assert ($manifest.content_security_policy.extension_pages.Contains('connect-src https://api.example.test;')) 'CSP origin mismatch.'
    $originalFile = [IO.File]::ReadAllText($file)
    [IO.File]::WriteAllText($file, $originalFile.Replace('https://api.example.test/prefix', 'https://updated.example.test'))
    Push-Location $work
    try {
        [Environment]::CurrentDirectory = $otherDirectory
        & (Join-Path $root 'configure-clients.ps1') -EnvFile './.env' -OutputRoot '.'
        Assert ((Get-Content -LiteralPath './extension/config.js' -Raw).Contains('https://updated.example.test')) 'Repeated generation ignored the edited .env or resolved relative output against the wrong directory.'
    } finally {
        [Environment]::CurrentDirectory = $netDirectory
        Pop-Location
        [IO.File]::WriteAllText($file, $originalFile)
    }
    $invalidFile = Join-Path $work 'invalid.env'
    [IO.File]::WriteAllText($invalidFile, "LOCKSTEP_API_BASE_URL=https://partial.example.test`nINVALID LINE`n")
    $rejected = $false
    try { Import-LockstepEnv -Path $invalidFile } catch { $rejected = $true }
    Assert ($rejected -and $null -eq [Environment]::GetEnvironmentVariable('LOCKSTEP_API_BASE_URL', 'Process')) 'Failed imports must not partially modify the terminal.'
    $env:GOOGLE_WEB_CLIENT_ID = 'older-test.apps.googleusercontent.com'
    Import-LockstepEnv -Path $file -OverrideExisting
    Assert ($env:GOOGLE_WEB_CLIENT_ID -eq 'web-test.apps.googleusercontent.com') 'Explicit .env reload failed to replace an old terminal value.'
    foreach ($name in $names) { Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue }
    $env:LOCKSTEP_API_BASE_URL = 'http://localhost:8089'
    $env:LOCKSTEP_USE_API_PROXY = 'true'
    & (Join-Path $root 'configure-clients.ps1') -EnvFile $file -OutputRoot $work
    Assert ((Get-Content -LiteralPath (Join-Path $work 'extension/config.js') -Raw).Contains('http://localhost:8089')) 'Process environment must override .env.'
    Assert ((Get-Content -LiteralPath (Join-Path $work 'webapp/config.js') -Raw).Contains('/lockstep')) 'Web proxy configuration missing.'
    $env:LOCKSTEP_API_BASE_URL = 'https://api.example.test; unsafe'
    $rejected = $false
    try { & (Join-Path $root 'configure-clients.ps1') -EnvFile $file -OutputRoot $work } catch { $rejected = $true }
    Assert $rejected 'Unsafe API configuration was accepted.'
    Write-Host 'Environment generation checks passed: repeated builds, relative paths, atomic imports, explicit reload, secret isolation, client IDs, CSP, permissions, precedence, proxy and invalid input.'
} finally {
    foreach ($name in $names) {
        if ($null -eq $saved[$name]) { Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue }
        else { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    }
    # Leave isolated test artifacts in the system temporary directory for inspection.
}
