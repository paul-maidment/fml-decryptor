# Build Native AOT release binaries for FmlDecryptor.
#
# Outputs clean binaries to dist/aot/<rid>/ (no PDBs, no SampleFiles).
#
# On Windows this script:
#   - Builds win-x64 and win-arm64 locally (requires VS 2022 C++ build tools)
#   - Builds linux-x64 and linux-arm64 via WSL or Docker when available
#   - Skips macOS targets (must be built on a Mac)
#
# Usage:
#   .\scripts\build-aot.ps1
#   .\scripts\build-aot.ps1 -Target linux-x64
#   .\scripts\build-aot.ps1 -Target win-x64,linux-x64 -Clean
#   .\scripts\build-aot.ps1 -Help

param(
    [string[]] $Target = @(),
    [switch] $Clean,
    [switch] $Help
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Dist = Join-Path $Root "dist\aot"
$Project = Join-Path $Root "FmlDecryptor.csproj"
$BashScript = Join-Path $PSScriptRoot "build-aot.sh"

$AllRids = @(
    "win-x64",
    "win-arm64",
    "linux-x64",
    "linux-arm64",
    "osx-x64",
    "osx-arm64"
)

function Show-Help {
    Get-Content $PSCommandPath | Select-Object -Skip 1 -First 14 | ForEach-Object {
        if ($_ -match "^# ?(.*)$") { $Matches[1] }
    }
    Write-Host ""
    Write-Host "Targets: $($AllRids -join ', ')"
}

if ($Help) {
    Show-Help
    exit 0
}

function Test-WslAvailable {
    $output = & wsl.exe --status 2>&1
    return $LASTEXITCODE -eq 0
}

function Test-DockerAvailable {
    return [bool](Get-Command docker -ErrorAction SilentlyContinue)
}

function Publish-Rid {
    param([string] $Rid)

    $out = Join-Path $Dist $Rid
    New-Item -ItemType Directory -Force -Path $out | Out-Null

    Write-Host "==> Publishing $Rid -> $out"
    & dotnet publish $Project `
        -c Release `
        -r $Rid `
        -p:PublishAot=true `
        --self-contained true `
        -o $out

    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed for $Rid with exit code $LASTEXITCODE"
    }

    $binaryName = if ($Rid -like "win-*") { "FmlDecryptor.exe" } else { "FmlDecryptor" }
    $binaryPath = Join-Path $out $binaryName
    if (-not (Test-Path $binaryPath)) {
        throw "Expected binary not found: $binaryPath"
    }

    Get-ChildItem -Path $out -Include *.pdb, *.dbg -Recurse -File -ErrorAction SilentlyContinue |
        Remove-Item -Force

    $sizeKb = [math]::Round((Get-Item $binaryPath).Length / 1KB, 1)
    Write-Host "    $sizeKb KB  $binaryPath"
}

function Invoke-BashBuild {
    param(
        [string[]] $Rids
    )

    if (-not (Test-Path $BashScript)) {
        throw "Missing $BashScript"
    }

    $bash = Get-Command bash -ErrorAction SilentlyContinue
    if (-not $bash) {
        throw "bash not found (install Git for Windows or use WSL/Docker for Linux targets)."
    }

    $linuxPath = ($Root -replace "\\", "/")
    if ($linuxPath -match "^([A-Za-z]):(.*)$") {
        $linuxPath = "/mnt/$($Matches[1].ToLower())$($Matches[2])"
    }

    $bashArgs = ($Rids | ForEach-Object { "'$_'" }) -join " "
    $command = "cd '$linuxPath' && bash ./scripts/build-aot.sh $bashArgs"

    Write-Host "==> Linux build via WSL"
    & wsl.exe -e bash -lc $command
    if ($LASTEXITCODE -ne 0) {
        throw "WSL build failed with exit code $LASTEXITCODE"
    }
}

function Invoke-DockerBuild {
    param(
        [string[]] $Rids
    )

    $argString = ($Rids | ForEach-Object { "'$_'" }) -join " "

    Write-Host "==> Linux build via Docker (mcr.microsoft.com/dotnet/sdk:8.0)"
    docker run --rm `
        -v "${Root}:/src" `
        -w /src `
        mcr.microsoft.com/dotnet/sdk:8.0 `
        bash -lc "apt-get update -qq && apt-get install -y -qq clang zlib1g-dev llvm > /dev/null && bash ./scripts/build-aot.sh $argString"

    if ($LASTEXITCODE -ne 0) {
        throw "Docker build failed with exit code $LASTEXITCODE"
    }
}

function Get-RequestedRids {
    if ($Target.Count -gt 0) {
        return $Target
    }
    return $AllRids
}

$requested = Get-RequestedRids
$windowsRids = @($requested | Where-Object { $_ -like "win-*" })
$linuxRids = @($requested | Where-Object { $_ -like "linux-*" })
$macRids = @($requested | Where-Object { $_ -like "osx-*" })

Write-Host "FmlDecryptor Native AOT build"
Write-Host "Project: $Project"
Write-Host "Output:  $Dist"
Write-Host "SDK:     $(dotnet --version)"
Write-Host ""

if ($Clean -and (Test-Path $Dist)) {
    Write-Host "Cleaning $Dist"
    Remove-Item -Recurse -Force $Dist
}

$failures = @()

foreach ($rid in $windowsRids) {
    try {
        Publish-Rid -Rid $rid
        Write-Host ""
    }
    catch {
        $failures += "Windows ($rid): $($_.Exception.Message)"
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Install Visual Studio 2022 with 'Desktop development with C++'." -ForegroundColor Yellow
        Write-Host "https://aka.ms/nativeaot-prerequisites" -ForegroundColor Yellow
    }
}

if ($linuxRids.Count -gt 0) {
    $linuxBuilt = $false
    foreach ($method in @("WSL", "Docker")) {
        if ($linuxBuilt) { break }

        try {
            if ($method -eq "WSL" -and (Test-WslAvailable)) {
                Invoke-BashBuild -Rids $linuxRids
                $linuxBuilt = $true
            }
            elseif ($method -eq "Docker" -and (Test-DockerAvailable)) {
                Invoke-DockerBuild -Rids $linuxRids
                $linuxBuilt = $true
            }
        }
        catch {
            Write-Host "WARN: $method Linux build failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    if (-not $linuxBuilt) {
        $msg = "Linux targets skipped (need WSL or Docker). Requested: $($linuxRids -join ', ')"
        $failures += $msg
        Write-Host $msg -ForegroundColor Yellow
        Write-Host "  WSL:    wsl --install" -ForegroundColor Yellow
        Write-Host "  Docker: https://docs.docker.com/desktop/setup/install/windows-install/" -ForegroundColor Yellow
    }
}

if ($macRids.Count -gt 0) {
    $msg = "macOS targets skipped (must build on a Mac): $($macRids -join ', ')"
    $failures += $msg
    Write-Host $msg -ForegroundColor Yellow
    Write-Host "  On macOS run: ./scripts/build-aot.sh $($macRids -join ' ')" -ForegroundColor Yellow
}

Write-Host ""
if (Test-Path $Dist) {
    Write-Host "Artifacts:"
    Get-ChildItem -Path $Dist -Recurse -File |
        Where-Object { $_.Extension -notin ".json" } |
        Sort-Object FullName |
        ForEach-Object {
            $sizeKb = [math]::Round($_.Length / 1KB, 1)
            Write-Host ("  {0,8} KB  {1}" -f $sizeKb, $_.FullName)
        }
}

$artifactCount = 0
if (Test-Path $Dist) {
    $artifactCount = @(Get-ChildItem -Path $Dist -Recurse -File |
        Where-Object { $_.Extension -notin ".json" }).Count
}

if ($artifactCount -eq 0) {
    Write-Host ""
    Write-Host "Build finished with no artifacts." -ForegroundColor Red
    exit 1
}

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host "Build completed with skipped targets." -ForegroundColor Yellow
    exit 2
}

Write-Host ""
Write-Host "Build complete." -ForegroundColor Green
