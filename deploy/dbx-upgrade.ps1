# DBX Web one-click upgrade: upload image tar + run remote-upgrade.sh on the server.
#
# Usage (PowerShell, from the repo root):
#   .\deploy\dbx-upgrade.ps1
#   .\deploy\dbx-upgrade.ps1 -Server 10.10.11.204 -User zjplan
#   .\deploy\dbx-upgrade.ps1 -SkipUpload        # only run the remote part (tar already uploaded)
#
# Notes:
# - Uses Windows built-in OpenSSH (ssh/scp). You will be asked for the password
#   once per command; configure an SSH key to avoid that.
# - Keeping this in PowerShell avoids Git Bash's path conversion, which would
#   rewrite values like /bridge/dbx into Windows paths.

[CmdletBinding()]
param(
  [string]$Server = "10.10.11.204",
  [string]$User = "zjplan",
  [string]$RemoteDir = "/home/zjplan/tools/dbx-waf",
  [string]$LocalTar = "dbx-waf.tar",
  [string]$RemoteTar = "dbx-waf-new.tar",
  [string]$Container = "dbx",
  [int]$Port = 4224,
  [string]$BasePath = "/bridge/dbx",
  [string]$WafKey = "dbx-waf-default-key-2026",
  [string]$DataDir = "/home/zjplan/tools/dbx-waf/data",
  [string]$BackupDir = "/home/zjplan/tools/dbx-waf/backups",
  [switch]$SkipUpload
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$tarPath = Join-Path $repoRoot $LocalTar
$remoteScript = Join-Path $repoRoot "deploy/remote-upgrade.sh"
$target = "$User@$Server"

if (-not $SkipUpload) {
  if (-not (Test-Path $tarPath)) {
    throw "Image tar not found: $tarPath (run 'docker save -o dbx-waf.tar dbx-waf:latest' first)"
  }
  $size = [math]::Round((Get-Item $tarPath).Length / 1MB, 1)
  $stamp = (Get-Item $tarPath).LastWriteTime.ToString("yyyy-MM-dd HH:mm")

  Write-Host "==> 1/4 Upload image tar ($size MB, $stamp) to ${target}:${RemoteDir}" -ForegroundColor Cyan
  & ssh $target "mkdir -p $RemoteDir; rm -f $RemoteDir/$RemoteTar"
  if ($LASTEXITCODE -ne 0) { throw "ssh mkdir failed" }
  & scp $tarPath "${target}:${RemoteDir}/${RemoteTar}"
  if ($LASTEXITCODE -ne 0) { throw "scp upload failed" }

  Write-Host "==> 2/4 Upload upgrade script" -ForegroundColor Cyan
  & scp $remoteScript "${target}:${RemoteDir}/remote-upgrade.sh"
  if ($LASTEXITCODE -ne 0) { throw "scp script failed" }
} else {
  Write-Host "==> Skip upload, reuse ${RemoteDir}/${RemoteTar}" -ForegroundColor Yellow
}

Write-Host "==> 3/4 Run remote upgrade (backup -> load -> recreate -> health check)" -ForegroundColor Cyan
$remoteCmd = "bash $RemoteDir/remote-upgrade.sh $RemoteDir/$RemoteTar dbx-waf:latest $Container $Port $BasePath $WafKey $DataDir $BackupDir"
& ssh $target $remoteCmd
$code = $LASTEXITCODE

Write-Host ""
if ($code -eq 0) {
  Write-Host "==> 4/4 Upgrade finished. Hard-refresh the browser (Ctrl+F5)." -ForegroundColor Green
  Write-Host "    Rollback: rebuild with dbx-waf:previous (see the header of deploy/remote-upgrade.sh)"
} else {
  Write-Host "==> 4/4 Upgrade FAILED (exit $code). Check the logs above." -ForegroundColor Red
  Write-Host "    Rollback: rebuild with dbx-waf:previous (see the header of deploy/remote-upgrade.sh)"
}
exit $code
