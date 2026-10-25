# Parse configuration as data, never as PowerShell. Existing process variables win.
function Read-LockstepEnv {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Configuration file not found: $Path. Copy .env.example to .env first." }
    # .NET's current directory can differ from PowerShell's provider location.
    # Resolve once through PowerShell before passing a path to a .NET file API.
    $resolvedPath = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    if ($resolvedPath.Provider.Name -ne 'FileSystem') { throw 'Configuration must be a filesystem file.' }
    $values = @{}
    $lineNumber = 0
    foreach ($original in [IO.File]::ReadAllLines($resolvedPath.ProviderPath)) {
        $lineNumber++
        $line = $original.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        if ($line.StartsWith('export ')) { $line = $line.Substring(7).Trim() }
        if ($line -notmatch '^([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$') { throw "Invalid .env assignment at line $lineNumber." }
        $name = $matches[1]; $value = $matches[2].Trim()
        if ($value.Length -ge 2 -and (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'")))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $values[$name] = $value
    }
    return $values
}

function Get-LockstepSetting {
    param([hashtable]$Values, [string]$Name, [string]$Default = '')
    $current = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if ($null -ne $current) { return $current }
    if ($Values.ContainsKey($Name)) { return $Values[$Name] }
    return $Default
}

function Import-LockstepEnv {
    param([Parameter(Mandatory)][string]$Path, [switch]$OverrideExisting)
    # Validate the entire file before changing any process variable.
    $values = Read-LockstepEnv -Path $Path
    foreach ($name in $values.Keys) {
        if ($OverrideExisting -or $null -eq [Environment]::GetEnvironmentVariable($name, 'Process')) {
            [Environment]::SetEnvironmentVariable($name, $values[$name], 'Process')
        }
    }
}
