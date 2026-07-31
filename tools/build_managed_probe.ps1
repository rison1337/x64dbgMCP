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

$dotnetOnPath = Get-Command dotnet.exe -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty Source
$x64Candidates = @($dotnetOnPath)
if ($env:ProgramFiles) {
    $x64Candidates += Join-Path $env:ProgramFiles "dotnet\dotnet.exe"
}
$x86Candidates = @()
$programFilesX86 = ${env:ProgramFiles(x86)}
if ($programFilesX86) {
    $x86Candidates += Join-Path $programFilesX86 "dotnet\dotnet.exe"
}

$x64Host = Resolve-DotNetHost -Explicit $DotNetX64 -Architecture "x64" -Candidates $x64Candidates
$x86Host = Resolve-DotNetHost -Explicit $DotNetX86 -Architecture "x86" -Candidates $x86Candidates

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
