[CmdletBinding()]
param(
    [string]$DotNetX64 = $env:X64DBG_MCP_DOTNET_X64,
    [string]$DotNetX86 = $env:X64DBG_MCP_DOTNET_X86
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$project = Join-Path $PSScriptRoot "managed_probe\ManagedProbe.csproj"
$outputRoot = Join-Path $PSScriptRoot "bin\managed_probe"

function Resolve-DotNetHost {
    param(
        [string]$Explicit,
        [string[]]$Candidates,
        [string]$Architecture
    )
    foreach ($candidate in @($Explicit) + $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw "A .NET 8 SDK host for $Architecture is required. Set X64DBG_MCP_DOTNET_$($Architecture.ToUpperInvariant())."
}

$x64Host = Resolve-DotNetHost -Explicit $DotNetX64 -Architecture "x64" -Candidates @(
    "C:\ai_slop\1\.dotnet-sdk\dotnet.exe",
    "C:\Program Files\dotnet\dotnet.exe"
)
$x86Host = Resolve-DotNetHost -Explicit $DotNetX86 -Architecture "x86" -Candidates @(
    "C:\ai_slop\1\.dotnet-sdk-x86\dotnet.exe",
    "C:\Program Files (x86)\dotnet\dotnet.exe"
)

foreach ($item in @(
    @{ Arch = "x64"; Rid = "win-x64"; Host = $x64Host },
    @{ Arch = "x86"; Rid = "win-x86"; Host = $x86Host }
)) {
    $output = Join-Path $outputRoot $item.Arch
    New-Item -ItemType Directory -Force -Path $output | Out-Null
    & $item.Host restore $project --runtime $item.Rid --nologo
    if ($LASTEXITCODE -ne 0) {
        throw "Managed probe restore failed for $($item.Arch)."
    }
    & $item.Host publish $project -c Release --runtime $item.Rid --self-contained false `
        --no-restore --nologo --output $output
    if ($LASTEXITCODE -ne 0) {
        throw "Managed probe publish failed for $($item.Arch)."
    }
    $exe = Join-Path $output "x64dbg.ManagedProbe.exe"
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        throw "Managed probe output is missing for $($item.Arch): $exe"
    }
    Write-Output "$($item.Arch): $exe"
}
