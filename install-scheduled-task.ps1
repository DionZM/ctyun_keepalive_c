# install-scheduled-task.ps1
# 注册 ctyun_keepalive 常驻守护的"自愈"计划任务（v1.5.1+）
#
# 机制：
#   - 登录触发 + 注册触发，均带每 5 分钟无限重复；守护常驻期间重复实例被
#     任务策略(IgnoreNew)和进程内命名互斥(Local\ctyun_keepalive_single_v1)双保险丢弃；
#     守护被外部强杀(如云平台 cloudbase-init / Restart Manager)后，最迟 5 分钟自动拉起。
#   - 动作直接以 /__bg 启动常驻实例（无闪窗、日志写 run.log），ExecutionTimeLimit=0 不超时。
#
# 用法：右键“使用 PowerShell 运行”，或在 PowerShell 中执行：
#   powershell -ExecutionPolicy Bypass -File .\install-scheduled-task.ps1
# 不需要管理员权限（任务以当前用户 InteractiveToken 运行）。

$ErrorActionPreference = "Stop"
$TaskName = "ctyun_keepalive"
$ExePath  = Join-Path $PSScriptRoot "ctyun_keepalive.exe"

if (-not (Test-Path -LiteralPath $ExePath)) {
    Write-Host "[ERROR] 找不到 $ExePath，请把脚本与 ctyun_keepalive.exe 放在同一目录" -ForegroundColor Red
    exit 1
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid      = $identity.User.Value
$account  = "$env:USERDOMAIN\$env:USERNAME"

$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>$account</Author>
    <Description>ctyun_keepalive resident self-heal: logon+registration triggers, 5min repetition; IgnoreNew + single-instance mutex</Description>
    <URI>\$TaskName</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>$sid</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <Hidden>true</Hidden>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
  </Settings>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>$account</UserId>
      <Repetition>
        <Interval>PT5M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </LogonTrigger>
    <RegistrationTrigger>
      <Enabled>true</Enabled>
      <Repetition>
        <Interval>PT5M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </RegistrationTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>$ExePath</Command>
      <Arguments>/__bg</Arguments>
      <WorkingDirectory>$PSScriptRoot</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

$tmpXml = Join-Path $env:TEMP "ctyun_keepalive_task.xml"
[IO.File]::WriteAllText($tmpXml, $xml, [Text.Encoding]::Unicode)

try {
    schtasks.exe /Create /TN $TaskName /XML $tmpXml /F | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "schtasks /Create 失败 (exit=$LASTEXITCODE)" }
}
finally {
    Remove-Item -LiteralPath $tmpXml -Force -ErrorAction SilentlyContinue
}

# 立即拉起一次（注册触发本身也会拉起，这里保证即时生效）
schtasks.exe /Run /TN $TaskName | Out-Null

Start-Sleep -Seconds 3
$proc = Get-Process ctyun_keepalive -ErrorAction SilentlyContinue
Write-Host "[OK] 计划任务 '$TaskName' 已注册（登录+每5分钟自愈重复）" -ForegroundColor Green
Write-Host "     程序: $ExePath /__bg"
if ($proc) {
    Write-Host "     守护已在运行 (PID $($proc.Id -join ','))" -ForegroundColor Green
} else {
    Write-Host "     [!] 未发现守护进程，请查 run.log；最迟 5 分钟内重复触发会再次拉起" -ForegroundColor Yellow
}
Write-Host "     卸载请运行 uninstall-scheduled-task.ps1"
