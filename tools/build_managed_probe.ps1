[CmdletBinding()]
param(
    [string]$DotNetX64 = $env:X64DBG_MCP_DOTNET_X64,
    [string]$DotNetX86 = $env:X64DBG_MCP_DOTNET_X86
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$project = Join-Path $PSScriptRoot "managed_probe\ManagedProbe.csproj"
$managedNotices = Join-Path $PSScriptRoot "managed_probe\THIRD-PARTY-NOTICES.txt"
$outputRoot = Join-Path $PSScriptRoot "bin\managed_probe"
$outputRootFull = [IO.Path]::GetFullPath($outputRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)

function Resolve-DotNetHost {
    param(
        [string[]]$Candidates
    )
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw "A .NET 8 SDK host is required. Set X64DBG_MCP_DOTNET_X64 to dotnet.exe from an SDK installation."
}

$dotnetOnPath = Get-Command dotnet.exe -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty Source
$sdkCandidates = @($DotNetX64, $DotNetX86, $dotnetOnPath)
if ($env:ProgramFiles) {
    $sdkCandidates += Join-Path $env:ProgramFiles "dotnet\dotnet.exe"
}
$programFilesX86 = ${env:ProgramFiles(x86)}
if ($programFilesX86) {
    $sdkCandidates += Join-Path $programFilesX86 "dotnet\dotnet.exe"
}

$sdkHost = Resolve-DotNetHost -Candidates $sdkCandidates
$sdkList = & $sdkHost --list-sdks
if ($LASTEXITCODE -ne 0 -or -not $sdkList) {
    throw "The selected dotnet host has no SDK. Install the .NET 8 SDK or set X64DBG_MCP_DOTNET_X64."
}
if (-not (Test-Path -LiteralPath $managedNotices -PathType Leaf)) {
    throw "Managed probe third-party notices are missing: $managedNotices"
}

function Copy-ManagedProbeNotices {
    param(
        [string]$Output,
        [string]$Rid
    )
    $depsPath = Join-Path $Output "x64dbg.ManagedProbe.deps.json"
    $assetsPath = Join-Path (Split-Path $project) "obj\project.assets.json"
    if (-not (Test-Path -LiteralPath $depsPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $assetsPath -PathType Leaf)) {
        throw "Managed probe dependency metadata is missing for $Rid."
    }
    $deps = Get-Content -Raw -LiteralPath $depsPath | ConvertFrom-Json
    $runtimePrefix = "runtimepack.Microsoft.NETCore.App.Runtime.$Rid/"
    $runtimeLibrary = $deps.libraries.PSObject.Properties |
        Where-Object { $_.Name.StartsWith($runtimePrefix, [StringComparison]::OrdinalIgnoreCase) } |
        Select-Object -First 1
    if (-not $runtimeLibrary) {
        throw "The published $Rid dependency graph has no .NET runtime pack."
    }
    $runtimeVersion = $runtimeLibrary.Name.Substring($runtimePrefix.Length)
    $assets = Get-Content -Raw -LiteralPath $assetsPath | ConvertFrom-Json
    $packageId = "microsoft.netcore.app.runtime.$($Rid.ToLowerInvariant())"
    $runtimePackage = $null
    foreach ($packageRoot in $assets.packageFolders.PSObject.Properties.Name) {
        $candidate = Join-Path (Join-Path $packageRoot $packageId) $runtimeVersion
        if (Test-Path -LiteralPath $candidate -PathType Container) {
            $runtimePackage = $candidate
            break
        }
    }
    if (-not $runtimePackage) {
        throw "The restored .NET runtime pack could not be located for $Rid $runtimeVersion."
    }
    $noticeMap = @{
        "LICENSE.TXT" = "DOTNET-RUNTIME-LICENSE.txt"
        "THIRD-PARTY-NOTICES.TXT" = "DOTNET-RUNTIME-THIRD-PARTY-NOTICES.txt"
    }
    foreach ($sourceName in $noticeMap.Keys) {
        $source = Join-Path $runtimePackage $sourceName
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "The .NET runtime pack notice is missing: $source"
        }
        Copy-Item -LiteralPath $source -Destination (Join-Path $Output $noticeMap[$sourceName])
    }
    Copy-Item -LiteralPath $managedNotices -Destination (
        Join-Path $Output "MANAGED-PROBE-THIRD-PARTY-NOTICES.txt"
    )
}

foreach ($item in @(
    @{ Arch = "x64"; Rid = "win-x64" },
    @{ Arch = "x86"; Rid = "win-x86" }
)) {
    $output = [IO.Path]::GetFullPath((Join-Path $outputRootFull $item.Arch))
    $requiredPrefix = $outputRootFull + [IO.Path]::DirectorySeparatorChar
    if (-not $output.StartsWith($requiredPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe managed probe output path: $output"
    }
    if (Test-Path -LiteralPath $output) {
        Remove-Item -LiteralPath $output -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $output | Out-Null
    & $sdkHost restore $project --runtime $item.Rid --nologo
    if ($LASTEXITCODE -ne 0) {
        throw "Managed probe restore failed for $($item.Arch)."
    }
    & $sdkHost publish $project -c Release --runtime $item.Rid --self-contained true `
        --no-restore --nologo --output $output
    if ($LASTEXITCODE -ne 0) {
        throw "Managed probe publish failed for $($item.Arch)."
    }
    $exe = Join-Path $output "x64dbg.ManagedProbe.exe"
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        throw "Managed probe output is missing for $($item.Arch): $exe"
    }
    foreach ($required in @("hostfxr.dll", "coreclr.dll")) {
        $requiredPath = Join-Path $output $required
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "Self-contained managed probe file is missing for $($item.Arch): $requiredPath"
        }
    }
    Copy-ManagedProbeNotices -Output $output -Rid $item.Rid
    Write-Output "$($item.Arch): $exe"
}
