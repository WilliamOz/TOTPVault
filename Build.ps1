param(
    [Parameter(Mandatory = $true)][string]$ServerIp,
    [Parameter(Mandatory = $true)][string]$AdHost,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'bin')
)

$ErrorActionPreference = 'Stop'
$address = $null
if (![Net.IPAddress]::TryParse($ServerIp, [ref]$address) -or
    $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'Use um IPv4 válido para o servidor.'
}
if ([Uri]::CheckHostName($AdHost) -ne [UriHostNameType]::Dns -or !$AdHost.Contains('.')) {
    throw 'Use o nome DNS completo do controlador LDAPS.'
}
$ServerIp = $address.ToString()
$root = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319'
$compiler = Join-Path $root 'csc.exe'
if (!(Test-Path -LiteralPath $compiler)) { throw 'Compilador do .NET Framework 4.8 indisponível.' }
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$out = (Resolve-Path -LiteralPath $OutputDirectory).Path
$build = Join-Path $out ('build-' + [guid]::NewGuid().ToString('N'))
$payload = Join-Path $build 'payload'
$null = New-Item -ItemType Directory -Path $payload

function Compile([string]$kind, [string]$exe, [string[]]$references, [string[]]$sources, [string[]]$extra = @()) {
    $framework = $references | ForEach-Object { '/reference:' + (Join-Path $root ($_ + '.dll')) }
    & $compiler /nologo "/target:$kind" /platform:anycpu /optimize+ /codepage:65001 "/out:$exe" @framework @extra @sources
    if ($LASTEXITCODE -ne 0) { throw "Falha ao compilar $([IO.Path]::GetFileName($exe))." }
}

try {
    $server = Join-Path $payload 'TOTPVault-Servidor.exe'
    $client = Join-Path $payload 'TOTPVault.exe'
    $installer = Join-Path $out 'Instalar-TOTPVault-Windows.exe'
    $serverSources = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'server') -Filter '*.cs' | ForEach-Object FullName)
    Compile 'exe' $server @('System.Security','System.ServiceProcess','System.DirectoryServices.Protocols','System.Web.Extensions') $serverSources

    $settings = Join-Path $build 'BuildSettings.g.cs'
    $url = ConvertTo-Json -InputObject "https://$ServerIp" -Compress
    [IO.File]::WriteAllText($settings, "namespace TotpVault { internal static class BuildSettings { internal const string ServerUrl = $url; }}")
    $clientSources = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'desktop') -Filter '*.cs' | ForEach-Object FullName) + @($settings)
    Compile 'winexe' $client @('System.Net.Http','System.Web.Extensions','System.Windows.Forms','System.Drawing') $clientSources

    $script = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'setup/Instalar.ps1'))
    [IO.File]::WriteAllText((Join-Path $payload 'Instalar.ps1'), $script, (New-Object Text.UTF8Encoding $true))
    $destination = Join-Path $payload 'implantacao.json'
    $defaults = @{ serverIp = $ServerIp; adHost = $AdHost } | ConvertTo-Json
    [IO.File]::WriteAllText($destination, $defaults, (New-Object Text.UTF8Encoding $true))
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'LICENSE') -Destination $payload
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = Join-Path $build 'payload.zip'
    [IO.Compression.ZipFile]::CreateFromDirectory($payload, $zip, [IO.Compression.CompressionLevel]::Optimal, $false)
    Compile 'exe' $installer @('System.IO.Compression','System.IO.Compression.FileSystem') @((Join-Path $PSScriptRoot 'setup/Bootstrap.cs')) @("/resource:$zip,totpvault-setup.zip")
    Copy-Item -LiteralPath $client -Destination (Join-Path $out 'TOTPVault-Windows-Nativo.exe') -Force
    & $installer --verify-payload
    if ($LASTEXITCODE -ne 0) { throw 'O instalador não contém todos os arquivos.' }
} finally {
    if (Test-Path -LiteralPath $build) { [IO.Directory]::Delete($build, $true) }
}
