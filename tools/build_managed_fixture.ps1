$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$source = Join-Path $repo "tests\fixtures\managed\ManagedException.cs"
$probeSource = Join-Path $repo "tests\fixtures\managed\ManagedProbeFixture.cs"
$payloadSource = Join-Path $repo "tests\fixtures\managed\ManagedDynamicPayload.cs"
$outRoot = Join-Path $repo "tools\bin\e2e"
$csc64 = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$csc32 = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"

if (-not (Test-Path -LiteralPath $source)) {
    throw "Managed fixture source is missing: $source"
}
if (-not (Test-Path -LiteralPath $probeSource)) {
    throw "Managed probe fixture source is missing: $probeSource"
}
if (-not (Test-Path -LiteralPath $payloadSource)) {
    throw "Managed dynamic payload source is missing: $payloadSource"
}
foreach ($item in @(
    @{ Arch = "x64"; Compiler = $csc64; Platform = "x64" },
    @{ Arch = "x86"; Compiler = $csc32; Platform = "x86" }
)) {
    if (-not (Test-Path -LiteralPath $item.Compiler)) {
        throw "Framework compiler is missing: $($item.Compiler)"
    }
    $outputDir = Join-Path $outRoot $item.Arch
    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
    $output = Join-Path $outputDir "managed_exception.exe"
    & $item.Compiler /nologo /target:exe /platform:$($item.Platform) /optimize+ /debug- `
        /out:$output $source
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $output)) {
        throw "Managed fixture compilation failed for $($item.Arch)"
    }
    Write-Output "$($item.Arch): $output"

    $payloadOutput = Join-Path $outputDir "ManagedProbeDynamicPayload.dll"
    & $item.Compiler /nologo /target:library /platform:anycpu /optimize+ /debug- `
        /out:$payloadOutput $payloadSource
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $payloadOutput)) {
        throw "Managed dynamic payload compilation failed for $($item.Arch)"
    }

    $probeOutput = Join-Path $outputDir "managed_probe_fixture.exe"
    $resourceOption = "/resource:$payloadOutput,ManagedProbeDynamicPayload.bin"
    & $item.Compiler /nologo /target:exe /platform:$($item.Platform) /optimize+ /debug- `
        $resourceOption "/out:$probeOutput" $probeSource
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $probeOutput)) {
        throw "Managed probe fixture compilation failed for $($item.Arch)"
    }
    Write-Output "$($item.Arch)-probe: $probeOutput"
}
