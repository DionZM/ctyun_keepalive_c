# uninstall-scheduled-task.ps1
# 停止并删除 ctyun_keepalive 自愈计划任务，同时结束正在运行的守护进程。
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File .\uninstall-scheduled-task.ps1

$ErrorActionPreference = "SilentlyContinue"
$TaskName = "ctyun_keepalive"

schtasks.exe /End  /TN $TaskName | Out-Null
schtasks.exe /Delete /TN $TaskName /F | Out-Null

Get-Process ctyun_keepalive -ErrorAction SilentlyContinue | Stop-Process -Force

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Write-Host "[ERROR] 任务 '$TaskName' 仍存在，请检查权限" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] 计划任务 '$TaskName' 已删除，守护进程已停止。" -ForegroundColor Green
Write-Host "     ctyun_points.exe / ctyun_keepalive.exe 文件未删除，可手动清理。"
