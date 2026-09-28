# Runs scripts/bootstrap_db.sql using the role passwords stored in .env.
# psql prompts for the postgres superuser password.
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

function Get-EnvValue([string]$File, [string]$Name) {
    $line = Get-Content $File | Where-Object { $_ -match "^$Name=" } | Select-Object -First 1
    if (-not $line) { throw "$Name is missing from $File" }
    return $line.Substring($Name.Length + 1)
}

function Get-UrlPassword([string]$Url) {
    if ($Url -match '^[^:]+://[^:]+:([^@]+)@') { return [uri]::UnescapeDataString($Matches[1]) }
    throw "No password found in database URL"
}

if (-not (Test-Path ".env")) { throw "Run 'uv run python scripts/make_dev_env.py' first." }
$ownerPw = Get-UrlPassword (Get-EnvValue ".env" "SECUREDB_MIGRATION_DATABASE_URL")
$appPw = Get-UrlPassword (Get-EnvValue ".env" "SECUREDB_DATABASE_URL")

psql -U postgres -h localhost -v ON_ERROR_STOP=1 -v "owner_pw=$ownerPw" -v "app_pw=$appPw" -f scripts/bootstrap_db.sql
if ($LASTEXITCODE -ne 0) { throw "psql failed with exit code $LASTEXITCODE" }
Write-Host "Databases securedb and securedb_test are ready."
