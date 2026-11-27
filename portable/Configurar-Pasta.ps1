$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Pasta-Comum.ps1')
Assert-TotpAdmin
Assert-TotpFolder

$init = Get-Content -Raw -LiteralPath (Join-Path $TotpRoot 'implantacao.json') | ConvertFrom-Json
$ip = [string]$init.serverIp
$port = 443
$address = '{0}:{1}' -f $ip,$port
$url = 'https://{0}:{1}/' -f $ip,$port
$ruleName = 'TOTPVault-Portatil-HTTPS'
$appId = '{dc222274-182a-4ccf-9f34-cc1c9564e1ba}'

function Run-Checked([string]$Tool, [string[]]$Arguments) {
    & $Tool @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Falha em $Tool (código $LASTEXITCODE)." }
}

$runtime = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue
if ($runtime.Release -lt 528040) { throw 'O .NET Framework 4.8 ou posterior é necessário.' }
if (!(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $ip -ErrorAction SilentlyContinue)) {
    throw "A máquina precisa ter o IP $ip."
}
if ((Test-Path -LiteralPath $TotpData) -or (Get-ScheduledTask -TaskName $TotpTask -ErrorAction SilentlyContinue) -or
    (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
    throw 'Já existe configuração desta pasta ou tarefa. Preserve os dados existentes e confira a configuração antes de continuar.'
}
if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
    Where-Object LocalAddress -In @($ip,'0.0.0.0','::')) {
    throw "A porta $port está ocupada no endereço $ip. Confira qual aplicação a utiliza."
}
if (Test-Path -LiteralPath ($TotpServer + '.config')) { throw 'Arquivo de configuração inesperado ao lado do servidor.' }

# Lock the program and deployment values before opening the LDAP probe under elevation.
Protect-TotpPath $TotpRoot 'ReadAndExecute'
foreach ($filename in 'TOTPVault-Servidor.exe','TOTPVault.exe','implantacao.json','Configurar-Pasta.ps1','Inicio-Automatico.ps1','Pasta-Comum.ps1') {
    Protect-TotpPath (Join-Path $TotpRoot $filename) 'ReadAndExecute'
}

$adHost = (Read-Host "Controlador LDAPS [$($init.adHost)]").Trim()
if (!$adHost) { $adHost = [string]$init.adHost }
$account = (Read-Host "UPN ou DN da conta de serviço somente leitura [$($init.bindIdentity)]").Trim()
if (!$account) { $account = [string]$init.bindIdentity }
if (!$account) { throw 'Informe o UPN ou DN da conta de serviço.' }
$administrators = (Read-Host 'DN completo do grupo de administradores do cofre').Trim()
if (!$administrators) { throw 'Informe o DN completo do grupo de administradores.' }
$access = (Read-Host 'DN do grupo que pode entrar no cofre (opcional)').Trim()
$baseDn = (Read-Host 'Base DN (Enter para detectar automaticamente)').Trim()
$thumb = ((Read-Host 'Thumbprint do certificado HTTPS corporativo (Enter para gerar um)') -replace '\s','').ToUpperInvariant()

Add-Type -AssemblyName System.Security
$password = Read-Host 'Senha da conta de serviço' -AsSecureString
if (!$password.Length) { throw 'Informe a senha da conta de serviço.' }
$memory = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
$raw = $null
try {
    $raw = [Text.Encoding]::UTF8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringBSTR($memory))
    $dpapi = [Security.Cryptography.ProtectedData]::Protect($raw,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
    $protected = [Convert]::ToBase64String($dpapi)
} finally {
    if ($raw) { [Array]::Clear($raw,0,$raw.Length) }
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($memory)
    $password.Dispose()
}

$config = [ordered]@{
    BindIp = $ip; Port = $port; AdHost = $adHost; AdPort = 636; BaseDn = $baseDn; BindIdentity = $account
    ProtectedBindPassword = $protected; AdminGroupDn = $administrators; AccessGroupDn = $access
}
$probe = Join-Path $TotpRoot ('probe-' + [Guid]::NewGuid().ToString('N'))
$probeConfig = Join-Path $probe 'servidor.json'
$serverConfig = Join-Path $TotpData 'servidor.json'
$export = Join-Path $TotpRoot 'TOTPVault-HTTPS.cer'
$madeCert = $null
$madeData = $false
$madeExport = $false
$urlAdded = $false
$tlsAdded = $false
$ruleAdded = $false
$utf8 = [Text.UTF8Encoding]::new($false)

try {
    $null = New-Item -ItemType Directory -Path $probe
    Protect-TotpPath $probe
    [IO.File]::WriteAllText($probeConfig,($config | ConvertTo-Json),$utf8)
    Write-Host 'Validando LDAPS e grupos com o controlador…'
    $resolved = & $TotpServer --probe $probe
    if ($LASTEXITCODE -ne 0) { throw 'Não foi possível validar o LDAPS. Confira certificado, CA e conta de serviço.' }
    if (!$baseDn) { $config.BaseDn = [string]($resolved | Select-Object -Last 1) }

    if ($thumb) {
        if ($thumb -cnotmatch '^[0-9A-F]{40}$') { throw 'Thumbprint do certificado HTTPS inválido.' }
        $cert = Get-Item -LiteralPath "Cert:\LocalMachine\My\$thumb"
        if (!$cert.HasPrivateKey -or $cert.NotBefore -gt (Get-Date) -or $cert.NotAfter -le (Get-Date)) {
            throw 'O certificado HTTPS precisa estar válido e conter a chave privada.'
        }
    } else {
        if (Test-Path -LiteralPath $export) { throw "Já existe um arquivo $export." }
        $options = @{
            Type='Custom'; Subject="CN=$ip"; CertStoreLocation='Cert:\LocalMachine\My'
            TextExtension=@("2.5.29.17={text}IPAddress=$ip",'2.5.29.37={text}1.3.6.1.5.5.7.3.1')
            KeyUsage=@('DigitalSignature','KeyEncipherment'); KeyExportPolicy='NonExportable'
            KeyAlgorithm='RSA'; KeyLength=2048; HashAlgorithm='SHA256'; NotAfter=(Get-Date).AddYears(1); FriendlyName='TOTPVault Portátil HTTPS'
        }
        $cert = New-SelfSignedCertificate @options
        $madeCert = $cert.Thumbprint
    }
    $config['HttpsThumbprint'] = $cert.Thumbprint

    $null = New-Item -ItemType Directory -Path $TotpData
    $madeData = $true
    Protect-TotpPath $TotpData 'Modify'
    [IO.File]::WriteAllText($serverConfig,($config | ConvertTo-Json),$utf8)
    Protect-TotpPath $serverConfig 'Read'

    Run-Checked "$env:SystemRoot\System32\netsh.exe" @('http','add','urlacl',"url=$url",'sddl=D:(A;;GX;;;S-1-5-19)(A;;GX;;;BA)')
    $urlAdded = $true
    Run-Checked "$env:SystemRoot\System32\netsh.exe" @('http','add','sslcert',"ipport=$address","certhash=$($cert.Thumbprint)","appid=$appId",'certstorename=MY')
    $tlsAdded = $true
    $firewall = @{
        Name=$ruleName; DisplayName='TOTPVault portátil HTTPS (rede local)'; Direction='Inbound'; Action='Allow'
        Protocol='TCP'; LocalAddress=$ip; LocalPort=$port; RemoteAddress='LocalSubnet'; Profile=@('Domain','Private')
    }
    $null = New-NetFirewallRule @firewall
    $ruleAdded = $true

    if ($madeCert) {
        $null = Export-Certificate -Cert $cert -FilePath $export
        $madeExport = $true
        Write-Host "Certificado público para a TI distribuir: $export"
        Write-Host ('SHA-256 do certificado: ' + (Get-FileHash -LiteralPath $export -Algorithm SHA256).Hash)
    }
    Write-Host "Pasta configurada. Execute .\Inicio-Automatico.ps1 para iniciar em $url e no boot."
} catch {
    $netsh = "$env:SystemRoot\System32\netsh.exe"
    if ($ruleAdded) { Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue }
    if ($tlsAdded) { & $netsh http delete sslcert "ipport=$address" | Out-Null }
    if ($urlAdded) { & $netsh http delete urlacl "url=$url" | Out-Null }
    if ($madeExport) { Remove-Item -LiteralPath $export -ErrorAction SilentlyContinue }
    if ($madeCert) { Remove-Item -LiteralPath "Cert:\LocalMachine\My\$madeCert" -ErrorAction SilentlyContinue }
    if ($madeData) {
        if (Test-Path -LiteralPath $serverConfig) { Remove-Item -LiteralPath $serverConfig -ErrorAction SilentlyContinue }
        if (!(Get-ChildItem -LiteralPath $TotpData -Force -ErrorAction SilentlyContinue)) {
            [IO.Directory]::Delete($TotpData)
        }
    }
    throw
} finally {
    if (Test-Path -LiteralPath $probeConfig) { Remove-Item -LiteralPath $probeConfig -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $probe -PathType Container) {
        if (!(Get-ChildItem -LiteralPath $probe -Force -ErrorAction SilentlyContinue)) { [IO.Directory]::Delete($probe) }
    }
}
