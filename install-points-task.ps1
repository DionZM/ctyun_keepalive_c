# install-points-task.ps1
# 为 ctyun_points.exe 添加每天 5:00 自动运行的计划任务

$ErrorActionPreference = "Stop"

$TaskName = "ctyun_points"
$ExePath = Join-Path $PSScriptRoot "ctyun_points.exe"

if (-not (Test-Path -LiteralPath $ExePath)) {
    Write-Host "[ERROR] exe not found: $ExePath" -ForegroundColor Red
    Write-Host "        Please compile ctyun_points.c first using build_points.bat"
    exit 1
}

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

if ($existing) {
    Write-Host "[INFO] Task '$TaskName' already exists, updating..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute $ExePath -WorkingDirectory $PSScriptRoot
$trigger = New-ScheduledTaskTrigger -Daily -At 5:00AM
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 420)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "ctyun_points daily 5AM points hanging task" -Force | Out-Null

Write-Host "[OK] Scheduled task '$TaskName' created." -ForegroundColor Green
Write-Host "      Trigger: daily at 5:00 AM"
Write-Host "      Command: $ExePath"
Write-Host "      WorkingDir: $PSScriptRoot"
Write-Host "      Time limit: 7 hours (adaptive hang hard-cap 6h + margin)"
