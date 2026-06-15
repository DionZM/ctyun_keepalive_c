# install-scheduled-task.ps1
# 为 ctyun_keepalive.exe 添加用户登录时自动运行的后台模式计划任务

$ErrorActionPreference = "Stop"

$TaskName = "ctyun_keepalive"
$ExePath = Join-Path $PSScriptRoot "ctyun_keepalive.exe"
$Arguments = "/b"

if (-not (Test-Path -LiteralPath $ExePath)) {
    Write-Host "[ERROR] exe not found: $ExePath" -ForegroundColor Red
    exit 1
}

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

if ($existing) {
    Write-Host "[INFO] Task '$TaskName' already exists, skipping." -ForegroundColor Yellow
    Write-Host "      Status: $($existing.State)"
    exit 0
}

$action = New-ScheduledTaskAction -Execute $ExePath -Argument $Arguments -WorkingDirectory $PSScriptRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "ctyun_keepalive auto-start on logon" -Force | Out-Null

Write-Host "[OK] Scheduled task '$TaskName' created." -ForegroundColor Green
Write-Host "      Trigger: user $env:USERNAME logon"
Write-Host "      Command: $ExePath $Arguments"
Write-Host "      WorkingDir: $PSScriptRoot"
