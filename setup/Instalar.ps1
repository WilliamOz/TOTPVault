$ErrorActionPreference = 'Stop'
$deployment = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'implantacao.json') | ConvertFrom-Json
$BindIp = [string]$deployment.serverIp
$service = 'TOTPVaultNative'
$firewall = 'TOTPVaultNative-LAN'
$appId = '{c5c4877c-8ce1-4c3b-832c-448cf3ceac5f}'
$program = Join-Path $env:ProgramFiles 'TOTPVaultNative'
$data = Join-Path $env:ProgramData 'TOTPVaultNative'
$serverSource = Join-Path $PSScriptRoot 'TOTPVault-Servidor.exe'
$clientSource = Join-Path $PSScriptRoot 'TOTPVault.exe'

function Run-Native([string]$file, [string[]]$arguments) {
    & $file @arguments
    if ($LASTEXITCODE -ne 0) { throw "Falha ao executar $([IO.Path]::GetFileName($file)). Código $LASTEXITCODE." }
}

function Require-Value([string]$label) {
    $value = (Read-Host $label).Trim()
    if ([string]::IsNullOrWhiteSpace($value)) { throw "Preencha $label e execute o instalador novamente." }
    return $value
}

function Protect-Directory([string]$path, [Security.Principal.SecurityIdentifier]$worker = $null) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($account in @('S-1-5-18','S-1-5-32-544')) {
        $sid = New-Object Security.Principal.SecurityIdentifier $account
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    if ($null -ne $worker) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($worker, 'Modify', $inherit, 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $path -AclObject $acl
}

$registered = $false
$urlAdded = $false
$tlsAdded = $false
$ruleAdded = $false
$programCreated = $false
$dataCreated = $false
$createdCertificate = $null
$probePath = Join-Path $env:ProgramData ('TOTPVaultProbe-' + [Guid]::NewGuid().ToString('N'))
$probeCreated = $false
$success = $false
try {
    $principal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Abra o instalador como administrador local.'
    }
    $net = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue
    if ($net.Release -lt 528040) { throw 'O .NET Framework 4.8 ou posterior é necessário.' }
    if (!(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $BindIp -ErrorAction SilentlyContinue)) {
        throw "O IP $BindIp não pertence a esta máquina. Execute no servidor certo."
    }
    if ((Get-Service -Name $service -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $program) -or
        (Test-Path -LiteralPath $data) -or (Get-NetFirewallRule -Name $firewall -ErrorAction SilentlyContinue)) {
        throw 'Já existe uma instalação ou configuração do TOTPVault. Preserve os dados antes de uma nova instalação.'
    }

    Write-Host "TOTPVault para Windows no servidor $BindIp" -ForegroundColor Cyan
    $port = 443
    $sockets = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue |
        Where-Object LocalAddress -In @($BindIp, '0.0.0.0', '::')
    if ($sockets) { throw "A porta $port já está em uso no endereço do cofre. O instalador não altera serviços existentes." }
    $prefix = 'https://{0}:{1}/' -f $BindIp, $port
    $address = '{0}:{1}' -f $BindIp, $port
    $ad = (Read-Host "Nome DNS do controlador LDAPS [$($deployment.adHost)]").Trim()
    if (!$ad) { $ad = [string]$deployment.adHost }
    $bind = Require-Value 'Usuário UPN ou DN da conta de serviço somente leitura do AD'
    $admin = Require-Value 'DN completo do grupo de administradores no AD'
    $access = (Read-Host 'DN do grupo de acesso ao cofre (opcional)').Trim()
    $base = (Read-Host 'Base DN (Enter para detectar a base padrão do AD)').Trim()
    $certId = ((Read-Host 'Thumbprint do certificado HTTPS corporativo (Enter para gerar um no Windows)') -replace '\s','').ToUpperInvariant()
    Add-Type -AssemblyName System.Security
    $password = Read-Host 'Senha da conta de serviço do AD' -AsSecureString
    if ($password.Length -lt 1) { throw 'A senha da conta de serviço é obrigatória.' }
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $raw = $null
    try {
        $raw = [Text.Encoding]::UTF8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer))
        $secret = [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($raw, $null,
            [Security.Cryptography.DataProtectionScope]::LocalMachine))
    } finally {
        if ($null -ne $raw) { [Array]::Clear($raw, 0, $raw.Length) }
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        $password.Dispose()
    }

    $settings = [ordered]@{
        BindIp = $BindIp; Port = $port; AdHost = $ad; AdPort = 636; BaseDn = $base
        BindIdentity = $bind; ProtectedBindPassword = $secret; AdminGroupDn = $admin; AccessGroupDn = $access
    }
    $null = New-Item -ItemType Directory -Path $probePath
    $probeCreated = $true
    Protect-Directory $probePath
    $utf8 = New-Object Text.UTF8Encoding $false
    $probeConfig = Join-Path $probePath 'servidor.json'
    [IO.File]::WriteAllText($probeConfig, ($settings | ConvertTo-Json), $utf8)
    Write-Host 'Validando LDAPS, Base DN e grupos com o controlador…'
    $resolved = & $serverSource --probe $probePath
    if ($LASTEXITCODE -ne 0) {
        throw 'Não foi possível validar o AD. Confira o DNS, a porta 636, a CA do controlador e a conta de serviço.'
    }
    if (!$base -and $resolved) { $settings.BaseDn = [string]($resolved | Select-Object -Last 1) }
    if ($certId) {
        if ($certId -cnotmatch '^[0-9A-F]{40}$') { throw 'Thumbprint HTTPS inválido.' }
        $cert = Get-Item -LiteralPath "Cert:\LocalMachine\My\$certId"
        if (!$cert.HasPrivateKey -or $cert.NotBefore -gt (Get-Date) -or $cert.NotAfter -le (Get-Date)) {
            throw 'O certificado HTTPS precisa estar válido e conter a chave privada.'
        }
    } else {
        $certificateOptions = @{
            Type = 'Custom'; Subject = "CN=$BindIp"; CertStoreLocation = 'Cert:\LocalMachine\My'
            TextExtension = @("2.5.29.17={text}IPAddress=$BindIp",'2.5.29.37={text}1.3.6.1.5.5.7.3.1')
            KeyUsage = 'DigitalSignature','KeyEncipherment'; KeyExportPolicy = 'NonExportable'
            KeyAlgorithm = 'RSA'; KeyLength = 2048; HashAlgorithm = 'SHA256'
            NotAfter = (Get-Date).AddYears(1); FriendlyName = 'TOTPVault HTTPS'
        }
        $cert = New-SelfSignedCertificate @certificateOptions
        $createdCertificate = $cert.Thumbprint
    }

    $null = New-Item -ItemType Directory -Path $program
    $programCreated = $true
    $server = Join-Path $program 'TOTPVault-Servidor.exe'
    Copy-Item -LiteralPath $serverSource -Destination $server
    Copy-Item -LiteralPath $clientSource -Destination $program
    $serviceOptions = @{
        Name = $service; BinaryPathName = ('"' + $server + '"'); DisplayName = 'TOTPVault - Cofre TOTP'
        Description = 'Cofre local de códigos TOTP com login Active Directory.'; StartupType = 'Manual'
    }
    $null = New-Service @serviceOptions
    $registered = $true
    Run-Native sc.exe @('config', $service, 'obj=', 'NT AUTHORITY\LocalService')
    Run-Native sc.exe @('sidtype', $service, 'unrestricted')
    $account = New-Object Security.Principal.NTAccount "NT SERVICE\$service"
    $sid = $account.Translate([Security.Principal.SecurityIdentifier])

    $null = New-Item -ItemType Directory -Path $data
    $dataCreated = $true
    Protect-Directory $data $sid
    [IO.File]::WriteAllText((Join-Path $data 'servidor.json'), ($settings | ConvertTo-Json), $utf8)
    Run-Native netsh.exe @('http', 'add', 'urlacl', "url=$prefix", "sddl=D:(A;;GX;;$($sid.Value))")
    $urlAdded = $true
    Run-Native netsh.exe @('http', 'add', 'sslcert', "ipport=$address", "certhash=$($cert.Thumbprint)", "appid=$appId", 'certstorename=MY')
    $tlsAdded = $true
    Start-Service -Name $service
    $healthy = $false
    for ($i = 0; $i -lt 8; $i++) {
        & $server --health ($prefix + 'healthz') $cert.Thumbprint
        if ($LASTEXITCODE -eq 0) { $healthy = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (!$healthy) { throw 'O serviço não respondeu por HTTPS. Confira se o certificado contém o IP configurado no SAN.' }

    $firewallOptions = @{
        Name = $firewall; DisplayName = 'TOTPVault HTTPS (rede local)'; Direction = 'Inbound'; Action = 'Allow'
        Protocol = 'TCP'; LocalAddress = $BindIp; LocalPort = $port; RemoteAddress = 'LocalSubnet'; Profile = 'Domain','Private'
    }
    $null = New-NetFirewallRule @firewallOptions
    $ruleAdded = $true
    Set-Service -Name $service -StartupType Automatic
    if ($createdCertificate) {
        $exportPath = Join-Path $program 'TOTPVault-HTTPS.cer'
        $null = Export-Certificate -Cert $cert -FilePath $exportPath
        Write-Host "Certificado público para a TI distribuir: $exportPath"
        Write-Host 'SHA-256 do certificado:'
        Write-Host (Get-FileHash -LiteralPath $exportPath -Algorithm SHA256).Hash
    }
    Write-Host "Cofre disponível em $prefix" -ForegroundColor Green
    Write-Host "Executável para os funcionários: $program\TOTPVault.exe"
    $success = $true
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    if ($registered) {
        Stop-Service -Name $service -ErrorAction SilentlyContinue
        & sc.exe delete $service | Out-Null
    }
    if ($ruleAdded) { Remove-NetFirewallRule -Name $firewall -ErrorAction SilentlyContinue }
    if ($tlsAdded) { & netsh.exe http delete sslcert "ipport=$address" | Out-Null }
    if ($urlAdded) { & netsh.exe http delete urlacl "url=$prefix" | Out-Null }
    if ($createdCertificate) { Remove-Item -LiteralPath "Cert:\LocalMachine\My\$createdCertificate" -ErrorAction SilentlyContinue }
    if ($programCreated -or $dataCreated) { Write-Host 'O serviço foi revertido. Os arquivos locais foram preservados para diagnóstico.' }
} finally {
    if ($probeCreated) {
        $probeConfig = Join-Path $probePath 'servidor.json'
        if (Test-Path -LiteralPath $probeConfig -PathType Leaf) {
            Remove-Item -LiteralPath $probeConfig -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $probePath -PathType Container) {
            if (!(Get-ChildItem -LiteralPath $probePath -Force)) {
                [IO.Directory]::Delete($probePath)
            }
        }
    }
}
Write-Host ''
$null = Read-Host 'Pressione Enter para sair'
if (!$success) { exit 1 }
