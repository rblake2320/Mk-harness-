<#
.SYNOPSIS
  Generate every secret the kernel stack needs and write them to a .env file.

.DESCRIPTION
  Windows-first. Uses the OS CSPRNG (System.Security.Cryptography) — never
  Get-Random. The Ed25519 assertion key pair is produced by the repo's own
  mk-devkeys binary so the encoding is exactly what the kernel verifies.
  Values are written with 0600-equivalent ACLs (owner only) and are never
  echoed. Idempotent: existing non-empty values are kept unless -Force.

.EXAMPLE
  pwsh -File scripts\kernel-secrets.ps1 -EnvFile .env
  pwsh -File scripts\kernel-secrets.ps1 -EnvFile .env -Force   # rotate everything
#>
[CmdletBinding()]
param(
  [string]$EnvFile = ".env",
  [switch]$Force,
  [string]$DevKeys = ""   # path to mk-devkeys; default: build/find in rust/target
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function New-RandomBytes([int]$n) {
  $b = [byte[]]::new($n)
  [System.Security.Cryptography.RandomNumberGenerator]::Fill($b)
  return $b
}
function New-Hex([int]$n) { ([System.BitConverter]::ToString((New-RandomBytes $n))).Replace("-", "").ToLower() }
function New-B64([int]$n) { [Convert]::ToBase64String((New-RandomBytes $n)) }

# -- locate or build mk-devkeys ------------------------------------------------
if (-not $DevKeys) {
  $cand = Join-Path $Root "rust\target\release\mk-devkeys.exe"
  if (-not (Test-Path $cand)) {
    Write-Host "building mk-devkeys (one time)…"
    Push-Location (Join-Path $Root "rust")
    try { cargo build --release -q --bin mk-devkeys } finally { Pop-Location }
  }
  $DevKeys = $cand
}
if (-not (Test-Path $DevKeys)) { throw "mk-devkeys not found at $DevKeys" }

# -- read existing file --------------------------------------------------------
$existing = @{}
if (Test-Path $EnvFile) {
  foreach ($line in Get-Content $EnvFile) {
    if ($line -match '^\s*([A-Z0-9_]+)=(.*)$') { $existing[$Matches[1]] = $Matches[2] }
  }
}
function Need([string]$k) { $Force -or -not $existing.ContainsKey($k) -or [string]::IsNullOrWhiteSpace($existing[$k]) }

$out = [ordered]@{}
foreach ($kv in $existing.GetEnumerator()) { $out[$kv.Key] = $kv.Value }

# -- core app secrets (main compose) -------------------------------------------
if (Need "POSTGRES_PASSWORD") { $out["POSTGRES_PASSWORD"] = New-Hex 24 }
if (Need "JWT_SECRET")        { $out["JWT_SECRET"]        = New-Hex 48 }
if (Need "MASTER_KEY")        { $out["MASTER_KEY"]        = New-B64 32 }

# -- assertion key pair via mk-devkeys ------------------------------------------
if ((Need "MK_ASSERTION_KEYS") -or (Need "KERNEL_ASSERTION_PRIVATE_KEY")) {
  $gen = & $DevKeys gen
  $pub  = ($gen | Where-Object { $_ -like "MK_ASSERTION_KEYS=*" }) -replace '^MK_ASSERTION_KEYS=', ''
  $priv = ($gen | Where-Object { $_ -like "DEV_PRIVATE_KEY=*" })   -replace '^DEV_PRIVATE_KEY=', ''
  if (-not $pub -or -not $priv) { throw "mk-devkeys gen produced no key pair" }
  $out["MK_ASSERTION_KEYS"] = $pub            # "k1=<b64url pubkey>"
  $out["KERNEL_ASSERTION_PRIVATE_KEY"] = $priv
  $out["KERNEL_ASSERTION_KID"] = "k1"
}

# -- per-process DB identities (>= 16 chars enforced by roles.sql) -------------
foreach ($k in "MK_DB_API_PASSWORD","MK_DB_WORKER_PASSWORD","MK_DB_RELAY_PASSWORD","MK_DB_READONLY_PASSWORD") {
  if (Need $k) { $out[$k] = New-Hex 24 }
}

# -- safe defaults (never enable dispatch here) ----------------------------------
if (-not $out.Contains("RUST_ACTION_KERNEL_ENABLED")) { $out["RUST_ACTION_KERNEL_ENABLED"] = "0" }
if (-not $out.Contains("KERNEL_PLATFORM_OPERATORS"))  { $out["KERNEL_PLATFORM_OPERATORS"]  = "" }
if (-not $out.Contains("MK_MOBILE_INTAKE_URL"))       { $out["MK_MOBILE_INTAKE_URL"]       = "" }
if (-not $out.Contains("MK_EGRESS_AUTHORITIES"))      { $out["MK_EGRESS_AUTHORITIES"]      = "" }

# -- atomic write, owner-only ACL, CRLF-safe (LF) ---------------------------------
$tmp = "$EnvFile.tmp"
$content = ($out.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "`n"
[System.IO.File]::WriteAllText($tmp, $content + "`n", [System.Text.UTF8Encoding]::new($false))
$acl = Get-Acl $tmp
$acl.SetAccessRuleProtection($true, $false)
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($me, "FullControl", "Allow")
$acl.ResetAccessRule($rule)
Set-Acl $tmp $acl
Move-Item -Force $tmp $EnvFile

Write-Host "wrote $EnvFile ($($out.Count) keys). RUST_ACTION_KERNEL_ENABLED=$($out['RUST_ACTION_KERNEL_ENABLED'])"
Write-Host "Next: scripts/kernel-preflight.sh (or .ps1 via WSL) before enabling dispatch."
