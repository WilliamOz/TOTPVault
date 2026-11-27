param(
    [string]$ServerUrl = '',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'bin')
)

$ErrorActionPreference = 'Stop'
$compilerRoot = Join-Path $env:WINDIR 'Microsoft.NET/Framework/v4.0.30319'
$compiler = Join-Path $compilerRoot 'csc.exe'
if (!(Test-Path -LiteralPath $compiler)) { throw 'O compilador do .NET Framework 4.8 não está disponível.' }
if ($ServerUrl) {
    $server = $null
    if (![uri]::TryCreate($ServerUrl, [UriKind]::Absolute, [ref]$server) -or $server.Scheme -ne 'https' -or
        !$server.Host -or $server.AbsolutePath -ne '/' -or $server.UserInfo -or $server.Query -or $server.Fragment) {
        throw 'Use uma URL HTTPS sem caminho, credenciais ou parâmetros.'
    }
    $ServerUrl = $server.AbsoluteUri
}
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$settings = Join-Path $OutputDirectory 'BuildSettings.g.cs'
try {
    $uriLiteral = ConvertTo-Json -InputObject $ServerUrl -Compress
    [IO.File]::WriteAllText($settings, 'namespace TotpVault { internal static class BuildSettings { internal const string ServerUrl = ' + $uriLiteral + '; }}')
    $sources = Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.cs' | ForEach-Object FullName
    $assemblies = 'System.Net.Http.dll','System.Web.Extensions.dll','System.Windows.Forms.dll','System.Drawing.dll'
    $references = $assemblies | ForEach-Object { '/reference:' + (Join-Path $compilerRoot $_) }
    $exe = Join-Path $OutputDirectory 'TOTPVault.exe'
    & $compiler /nologo /target:winexe /platform:anycpu /optimize+ /codepage:65001 "/out:$exe" @references $settings @sources
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao compilar TOTPVault.exe.' }
    Get-Item -LiteralPath $exe
} finally {
    if (Test-Path -LiteralPath $settings) { Remove-Item -LiteralPath $settings }
}
