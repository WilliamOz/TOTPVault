param(
    [Parameter(Mandatory = $true)][string]$ServerIp,
    [Parameter(Mandatory = $true)][string]$AdHost,
    [string]$BindIdentity = '',
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
$payload = Join-Path $build 'TOTPVault'
$null = New-Item -ItemType Directory -Path $payload

function Compile([string]$kind, [string]$exe, [string[]]$references, [string[]]$sources, [string[]]$extra = @()) {
    $framework = $references | ForEach-Object { '/reference:' + (Join-Path $root ($_ + '.dll')) }
    & $compiler /nologo "/target:$kind" /platform:anycpu /optimize+ /codepage:65001 "/out:$exe" @framework @extra @sources
    if ($LASTEXITCODE -ne 0) { throw "Falha ao compilar $([IO.Path]::GetFileName($exe))." }
}

try {
    $server = Join-Path $payload 'TOTPVault-Servidor.exe'
    $client = Join-Path $payload 'TOTPVault.exe'
    $serverSources = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'server') -Filter '*.cs' | ForEach-Object FullName)
    Compile 'exe' $server @('System.Security','System.DirectoryServices.Protocols','System.Web.Extensions') $serverSources

    $settings = Join-Path $build 'BuildSettings.g.cs'
    $url = ConvertTo-Json -InputObject "https://$ServerIp" -Compress
    [IO.File]::WriteAllText($settings, "namespace TotpVault { internal static class BuildSettings { internal const string ServerUrl = $url; }}")
    $clientSources = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'desktop') -Filter '*.cs' | ForEach-Object FullName) + @($settings)
    Compile 'winexe' $client @('System.Net.Http','System.Web.Extensions','System.Windows.Forms','System.Drawing') $clientSources

    foreach ($script in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'portable') -Filter '*.ps1' -File) {
        $body = [IO.File]::ReadAllText($script.FullName)
        [IO.File]::WriteAllText((Join-Path $payload $script.Name), $body, [Text.UTF8Encoding]::new($true))
    }
    $destination = Join-Path $payload 'implantacao.json'
    $defaults = @{ serverIp = $ServerIp; adHost = $AdHost; bindIdentity = $BindIdentity } | ConvertTo-Json
    [IO.File]::WriteAllText($destination, $defaults, (New-Object Text.UTF8Encoding $true))
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'LICENSE') -Destination $payload
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination (Join-Path $payload 'LEIA-ME.md')
    $source = Join-Path $payload 'fontes'
    $null = New-Item -ItemType Directory -Path $source
    foreach ($part in 'Build.ps1','README.md','LICENSE','server','desktop','portable','tests') {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $part) -Destination $source -Recurse
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $hashes = Get-ChildItem -LiteralPath $payload -File -Recurse | Sort-Object FullName | ForEach-Object {
        $relative = $_.FullName.Substring($payload.Length + 1).Replace('\','/')
        '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash, $relative
    }
    [IO.File]::WriteAllLines((Join-Path $payload 'SHA256SUMS.txt'), [string[]]$hashes)
    $zip = Join-Path $build 'TOTPVault-Portatil.zip'
    [IO.Compression.ZipFile]::CreateFromDirectory($payload, $zip, [IO.Compression.CompressionLevel]::Optimal, $true)
    Copy-Item -LiteralPath $zip -Destination $out -Force
} finally {
    $scratch = Get-Item -LiteralPath $build -ErrorAction SilentlyContinue
    if ($scratch -and $scratch.Parent.FullName -eq $out.TrimEnd([char[]]'\/') -and
        $scratch.Name -cmatch '^build-[0-9a-f]{32}$' -and !$scratch.LinkType) {
        [IO.Directory]::Delete($scratch.FullName, $true)
    }
}
