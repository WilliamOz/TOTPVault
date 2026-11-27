$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Pasta-Comum.ps1')
Assert-TotpAdmin
$config = Read-TotpConfig
if (Test-Path -LiteralPath ($TotpServer + '.config')) { throw 'Arquivo de configuração inesperado ao lado do servidor.' }

$action = New-ScheduledTaskAction -Execute $TotpServer -Argument ('--portable "' + $TotpData + '"') -WorkingDirectory $TotpRoot
$trigger = New-ScheduledTaskTrigger -AtStartup
$account = $TotpLocalService.Translate([Security.Principal.NTAccount]).Value
$principal = New-ScheduledTaskPrincipal -UserId $account -LogonType ServiceAccount -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval ([TimeSpan]::FromMinutes(1)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

if (Get-ScheduledTask -TaskName $TotpTask -ErrorAction SilentlyContinue) {
    throw "A tarefa $TotpTask já existe. Use Start-ScheduledTask -TaskName '$TotpTask' para iniciá-la."
}

$health = 'https://{0}:{1}/healthz' -f $config.BindIp,$config.Port
& $TotpServer --health $health $config.HttpsThumbprint
if ($LASTEXITCODE -eq 0) { throw 'O servidor já está em execução. Pare a instância manual antes de registrar o início automático.' }

$null = Register-ScheduledTask -TaskName $TotpTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Inicia o cofre TOTPVault portátil ao ligar o Windows.'
Start-ScheduledTask -TaskName $TotpTask
for ($i=0; $i -lt 12; $i++) {
    & $TotpServer --health $health $config.HttpsThumbprint
    if ($LASTEXITCODE -eq 0) {
        Write-Host "TOTPVault iniciado. A tarefa $TotpTask iniciará o cofre quando o Windows ligar."
        return
    }
    Start-Sleep -Milliseconds 650
}
throw "A tarefa $TotpTask foi registrada, mas o HTTPS não respondeu. Confira seu resultado no Agendador e o arquivo dados\servico.log."
