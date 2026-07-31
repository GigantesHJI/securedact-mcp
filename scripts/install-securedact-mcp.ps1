[CmdletBinding()]
param(
    [ValidateSet("English", "Dutch", "All", "None")]
    [string]$Language,

    [switch]$AcceptUpstreamTerms,

    [string]$InstallDirectory,

    [string]$PackageSource
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python Launcher for Windows is required. Install Python 3.12, then retry."
}

& py -3.12 -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "Python 3.12 is required."
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
if (-not $InstallDirectory) {
    if (-not $env:LOCALAPPDATA) {
        throw "LOCALAPPDATA is unavailable; provide -InstallDirectory."
    }
    $InstallDirectory = Join-Path $env:LOCALAPPDATA "Securedact\MCP\runtime"
}
if (-not $PackageSource) {
    $PackageSource = $repositoryRoot
}

$resolvedInstallDirectory = [System.IO.Path]::GetFullPath($InstallDirectory)
New-Item -ItemType Directory -Path $resolvedInstallDirectory -Force | Out-Null
$virtualEnvironment = Join-Path $resolvedInstallDirectory ".venv"

if (-not (Test-Path (Join-Path $virtualEnvironment "Scripts\python.exe"))) {
    & py -3.12 -m venv $virtualEnvironment
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the Python 3.12 virtual environment."
    }
}

$python = Join-Path $virtualEnvironment "Scripts\python.exe"
$securedact = Join-Path $virtualEnvironment "Scripts\securedact-mcp.exe"

& $python -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "The existing virtual environment does not use Python 3.12. Choose another installation directory."
}

& $python -m pip install "${PackageSource}[ml]"
if ($LASTEXITCODE -ne 0) {
    throw "Securedact MCP package installation failed."
}

$installArguments = @("install")
if ($Language) {
    $installArguments += @("--language", $Language.ToLowerInvariant())
}
if ($AcceptUpstreamTerms) {
    $installArguments += "--accept-upstream-terms"
}

& $securedact @installArguments
if ($LASTEXITCODE -ne 0) {
    throw "Securedact MCP model setup did not complete."
}

& $securedact models verify
if ($LASTEXITCODE -ne 0) {
    throw "The selected Securedact MCP models did not pass verification."
}

$previousEntrypoint = $env:SECUREDACT_ENTRYPOINT
$env:SECUREDACT_ENTRYPOINT = $securedact
& $python (Join-Path $PSScriptRoot "smoke_test_entrypoint.py")
$smokeExitCode = $LASTEXITCODE
if ($null -eq $previousEntrypoint) {
    Remove-Item Env:SECUREDACT_ENTRYPOINT -ErrorAction SilentlyContinue
} else {
    $env:SECUREDACT_ENTRYPOINT = $previousEntrypoint
}
if ($smokeExitCode -ne 0) {
    throw "The installed MCP entry point failed its local smoke test."
}

Write-Host ""
Write-Host "Securedact MCP installation is ready."
Write-Host ""
Write-Host "Codex configuration:"
Write-Host "[mcp_servers.securedact]"
Write-Host "command = '$securedact'"
Write-Host "cwd = '$resolvedInstallDirectory'"
Write-Host "required = true"
Write-Host ""
Write-Host "The MCP server uses stdio and waits for the host after startup."
