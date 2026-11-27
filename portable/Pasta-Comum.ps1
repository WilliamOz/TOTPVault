$TotpRoot = (Get-Item -LiteralPath $PSScriptRoot).FullName
$TotpServer = Join-Path $TotpRoot 'TOTPVault-Servidor.exe'
$TotpData = Join-Path $TotpRoot 'dados'
$TotpTask = 'TOTPVault-Portatil'
$TotpLocalService = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')

function Assert-TotpFolder {
    $expected = Join-Path $env:SystemDrive 'TOTPVault'
    if ($TotpRoot -ne $expected -or (Get-Item -LiteralPath $TotpRoot).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        throw "Extraia a pasta TOTPVault no disco do Windows, em $expected."
    }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($TotpRoot))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -ne 'NTFS') {
        throw 'A pasta do servidor deve estar em um disco local NTFS.'
    }
    foreach ($name in 'TOTPVault-Servidor.exe','TOTPVault.exe','implantacao.json') {
        $file = Join-Path $TotpRoot $name
        if (!(Test-Path -LiteralPath $file -PathType Leaf) -or
            (Get-Item -LiteralPath $file).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
            throw "Arquivo inválido ou ausente: $name."
        }
    }
}

function Assert-TotpAdmin {
    $user = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$user.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Abra o Windows PowerShell como administrador local.'
    }
}

function Protect-TotpPath([string]$Path, [string]$WorkerRights = '') {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw 'Caminho vinculado inesperado.' }
    $admin = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $flags = [Security.AccessControl.InheritanceFlags]::None
    if ($item.PSIsContainer) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $flags = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    } else {
        $acl = [Security.AccessControl.FileSecurity]::new()
    }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($admin)
    foreach ($sid in @($admin,$system)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', $flags, 'None', 'Allow'))
    }
    if ($WorkerRights) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($TotpLocalService, $WorkerRights, $flags, 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-TotpProtected([string]$Path, [bool]$WorkerMayWrite = $false) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw "Caminho vinculado inesperado: $Path" }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-32-544','S-1-5-18')) { throw "Proprietário inesperado: $Path" }
    $safe = @('S-1-5-18','S-1-5-32-544','S-1-5-19')
    $write = [int][Security.AccessControl.FileSystemRights]::Write -bor [int][Security.AccessControl.FileSystemRights]::Delete -bor
        [int][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [int][Security.AccessControl.FileSystemRights]::ChangePermissions -bor [int][Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $rule.IdentityReference.Value
        if ($sid -notin $safe -or ($sid -eq $TotpLocalService.Value -and !$WorkerMayWrite -and
            (([int]$rule.FileSystemRights -band $write) -ne 0))) {
            throw "Permissões inesperadas em $Path. Confira a preparação da pasta."
        }
    }
}

function Read-TotpConfig {
    Assert-TotpFolder
    if (!(Test-Path -LiteralPath (Join-Path $TotpData 'servidor.json') -PathType Leaf)) {
        throw 'Execute Configurar-Pasta.ps1 como administrador antes de iniciar.'
    }
    Assert-TotpProtected $TotpRoot
    Assert-TotpProtected $TotpServer
    Assert-TotpProtected $TotpData $true
    $path = Join-Path $TotpData 'servidor.json'
    Assert-TotpProtected $path
    $config = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
    if ($config.Port -ne 443 -or [string]$config.HttpsThumbprint -cnotmatch '^[0-9A-F]{40}$') {
        throw 'Configuração HTTPS incompleta.'
    }
    return $config
}
