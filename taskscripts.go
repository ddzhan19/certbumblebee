package main

// PowerShell-Skripte für die Windows-Aufgabenplanung und die Firewall.
// Werte kommen über Umgebungsvariablen (ZA_*), nie über die Befehlszeile. So bleibt ein Kontopasswort
// aus der Prozessliste heraus und Sonderzeichen brauchen kein Quoting.

const psPrefix = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
`

const psSuffix = `
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
`

const psTaskRegister = `
$action = New-ScheduledTaskAction -Execute $env:ZA_TASK_EXE -Argument $env:ZA_TASK_ARGS -WorkingDirectory $env:ZA_TASK_WORK
$trigger = New-ScheduledTaskTrigger -Daily -At $env:ZA_TASK_TIME -RandomDelay (New-TimeSpan -Minutes 30)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 15)
$desc = 'Erneuert das Zertifikat automatisch (Certbumblebee).'
if ($env:ZA_TASK_USER -eq 'SYSTEM') {
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $env:ZA_TASK_NAME -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $desc -Force | Out-Null
} else {
    Register-ScheduledTask -TaskName $env:ZA_TASK_NAME -Action $action -Trigger $trigger -Settings $settings -User $env:ZA_TASK_USER -Password $env:ZA_TASK_PASS -RunLevel Highest -Description $desc -Force | Out-Null
}
`

// Exit-Code 3: Aufgabe existiert nicht.
const psTaskExists = `
if (Get-ScheduledTask -TaskName $env:ZA_TASK_NAME -ErrorAction SilentlyContinue) { exit 0 } else { exit 3 }
`

const psTaskDelete = `
Unregister-ScheduledTask -TaskName $env:ZA_TASK_NAME -Confirm:$false
`

const psTaskRun = `
Start-ScheduledTask -TaskName $env:ZA_TASK_NAME
`

const psFirewallAdd = `
Get-NetFirewallRule -DisplayName $env:ZA_FW_NAME -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $env:ZA_FW_NAME -Direction Inbound -Action Allow -Protocol TCP -LocalPort $env:ZA_FW_PORT -Program $env:ZA_FW_PROGRAM -Profile Any | Out-Null
`

const psFirewallRemove = `
Get-NetFirewallRule -DisplayName $env:ZA_FW_NAME -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
`

func wrapPS(body string) string { return psPrefix + body + psSuffix }
