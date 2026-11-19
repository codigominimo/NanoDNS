<#
.SYNOPSIS
Builds NanoDNS for Windows x86_64/ARM64 and Linux x86_64/ARM64.

.DESCRIPTION
Builds four release binaries and copies each one, together with the default
configuration, into dist/<target>.

Prerequisites:
  - rustup targets for all four triples.
  - Visual Studio Build Tools with the x64 and ARM64 VC toolsets and the
    Windows SDK (ARM64 libs) for the MSVC targets.
  - LLVM (clang-cl and llvm-lib) for the C code compiled by ring/sqlite.
  - cargo-zigbuild and Zig for the Linux targets, or matching cross GCCs.
    If cargo-zigbuild is not on PATH, plain cargo is used instead.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File scripts/build-all.ps1

.EXAMPLE
powershell -ExecutionPolicy Bypass -File scripts/build-all.ps1 -Targets x86_64-pc-windows-msvc,aarch64-pc-windows-msvc -SkipUnavailable
#>
param(
    [ValidateSet('Debug', 'Release')]
    [string] $Profile = 'Release',
    [string[]] $Targets = @(
        'x86_64-pc-windows-msvc',
        'aarch64-pc-windows-msvc',
        'x86_64-unknown-linux-gnu',
        'aarch64-unknown-linux-gnu'
    ),
    [switch] $SkipUnavailable
)

$ErrorActionPreference = 'Stop'
$cargoProfile = $Profile.ToLowerInvariant()
$root = Split-Path -Parent $PSScriptRoot
$failed = @()
$originalPath = $env:Path
$originalLib = $env:LIB

# Configure LLVM and the MSVC ARM64 cross toolchain. Returns $false with a
# clear message when a prerequisite is missing.
function Set-WindowsArm64Environment {
    $clangCl = Get-Command clang-cl -ErrorAction SilentlyContinue
    $llvmLib = Get-Command llvm-lib -ErrorAction SilentlyContinue
    if (-not $clangCl -or -not $llvmLib) {
        Write-Warning 'Install LLVM (clang-cl and llvm-lib) to build ring/sqlite for ARM64.'
        return $false
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) {
        Write-Warning 'Visual Studio Installer not found; install the VC ARM64 build tools.'
        return $false
    }
    $install = & $vswhere -products '*' -property installationPath | Select-Object -First 1
    if (-not $install) {
        Write-Warning 'No Visual Studio installation found.'
        return $false
    }
    $msvcVersions = Get-ChildItem (Join-Path $install 'VC\Tools\MSVC') -Directory -ErrorAction SilentlyContinue
    $msvc = $msvcVersions | Sort-Object Name -Descending | Select-Object -First 1
    $sdkVersions = Get-ChildItem (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Lib') -Directory -ErrorAction SilentlyContinue
    $sdk = $sdkVersions | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $msvc -or -not $sdk) {
        Write-Warning 'VC tools or Windows SDK not found.'
        return $false
    }

    $hostBin = Join-Path $msvc.FullName 'bin\Hostx64\x64'
    $vcLib = Join-Path $msvc.FullName 'lib\arm64'
    $umLib = Join-Path $sdk.FullName 'um\arm64'
    $ucrtLib = Join-Path $sdk.FullName 'ucrt\arm64'
    if (-not (Test-Path $vcLib) -or -not (Test-Path $umLib) -or -not (Test-Path $ucrtLib)) {
        Write-Warning 'Install the VC ARM64 build tools and the Windows SDK ARM64 libraries.'
        return $false
    }

    $env:Path = "$hostBin;$env:Path"
    $env:LIB = "$vcLib;$umLib;$ucrtLib"
    $env:CC_aarch64_pc_windows_msvc = 'clang-cl'
    $env:CFLAGS_aarch64_pc_windows_msvc = '--target=aarch64-pc-windows-msvc'
    $env:AR_aarch64_pc_windows_msvc = 'llvm-lib'
    return $true
}

Push-Location $root
try {
    foreach ($target in $Targets) {
        $env:Path = $originalPath
        $env:LIB = $originalLib
        Remove-Item Env:CC_aarch64_pc_windows_msvc -ErrorAction SilentlyContinue
        Remove-Item Env:CFLAGS_aarch64_pc_windows_msvc -ErrorAction SilentlyContinue
        Remove-Item Env:AR_aarch64_pc_windows_msvc -ErrorAction SilentlyContinue

        if ((rustup target list --installed) -notcontains $target) {
            Write-Host "Adding Rust target $target"
            rustup target add $target
            if ($LASTEXITCODE -ne 0) {
                $failed += $target
                Write-Warning "Cannot install target $target."
                if (-not $SkipUnavailable) { break }
                continue
            }
        }

        if ($target -eq 'aarch64-pc-windows-msvc' -and -not (Set-WindowsArm64Environment)) {
            $failed += $target
            if (-not $SkipUnavailable) { break }
            continue
        }

        # cargo-zigbuild supplies the C cross toolchain for the Linux targets.
        $useZig = $target -like '*linux*' -and (Get-Command cargo-zigbuild -ErrorAction SilentlyContinue)
        $cargoArgs = @()
        if ($useZig) { $cargoArgs += 'zigbuild' } else { $cargoArgs += 'build' }
        $cargoArgs += @('--profile', $cargoProfile, '--target', $target, '-p', 'nano-dns')

        Write-Host "Building $target ($cargoProfile)"
        & cargo @cargoArgs
        if ($LASTEXITCODE -ne 0) {
            $failed += $target
            Write-Warning "Build failed for $target. Check that the matching C/C++ cross toolchain is installed."
            if (-not $SkipUnavailable) { break }
            continue
        }

        $binary = if ($target -like '*windows*') { 'nano-dns.exe' } else { 'nano-dns' }
        $source = Join-Path $root "target\$target\$cargoProfile\$binary"
        $destination = Join-Path $root "dist\$target"
        New-Item -ItemType Directory -Force -Path $destination | Out-Null
        Copy-Item $source $destination -Force
        Copy-Item (Join-Path $root 'config\nano-dns.json') $destination -Force
        Write-Host "Artifact: $destination"
    }
}
finally {
    Pop-Location
    $env:Path = $originalPath
    $env:LIB = $originalLib
}

if ($failed.Count -gt 0) {
    Write-Warning ("Failed targets: " + ($failed -join ', '))
    if ($SkipUnavailable) { exit 0 }
    exit 1
}

Write-Host "All targets built successfully."
