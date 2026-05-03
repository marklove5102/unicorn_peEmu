param(
    [Parameter(Mandatory = $true)][string]$SolutionDir,
    [Parameter(Mandatory = $true)][string]$Platform,
    [Parameter(Mandatory = $true)][string]$Configuration
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path $SolutionDir).Path
$arch = if ($Platform -eq "Win32") { "Win32" } else { "x64" }
$buildDir = Join-Path $root "unicorn-master\build-msvc-$arch"
$libDir = Join-Path $root "lib\$arch\$Configuration"

function Find-VSGenerator {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vs2019 = & $vswhere -version "[16.0,17.0)" -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($vs2019) { return "Visual Studio 16 2019" }

        $vs2022 = & $vswhere -version "[17.0,18.0)" -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($vs2022) { return "Visual Studio 17 2022" }
    }

    return "Visual Studio 16 2019"
}

$generator = Find-VSGenerator

$cacheFile = Join-Path $buildDir "CMakeCache.txt"
if (Test-Path $cacheFile) {
    $cachedGenerator = Select-String -Path $cacheFile -Pattern "^CMAKE_GENERATOR:INTERNAL=(.+)$" | Select-Object -First 1
    if ($cachedGenerator -and $cachedGenerator.Matches[0].Groups[1].Value -ne $generator) {
        Remove-Item -LiteralPath $buildDir -Recurse -Force
    }
}

cmake -S (Join-Path $root "unicorn-master") `
      -B $buildDir `
      -G $generator `
      -A $arch `
      -DUNICORN_ARCH=x86 `
      -DUNICORN_BUILD_TESTS=OFF `
      -DUNICORN_INSTALL=OFF `
      -DBUILD_SHARED_LIBS=ON `
      -DUNICORN_LEGACY_STATIC_ARCHIVE=ON

cmake --build $buildDir --config $Configuration --target unicorn_static --parallel

New-Item -ItemType Directory -Force -Path $libDir | Out-Null

$ucLibs = @("unicorn_static.lib", "unicorn-common.lib", "x86_64-softmmu.lib")
foreach ($lib in $ucLibs) {
    Copy-Item -Force (Join-Path $buildDir "$Configuration\$lib") (Join-Path $libDir $lib)
}

$capstoneName = if ($arch -eq "Win32") { "capstone_x86.lib" } else { "capstone_x64.lib" }
Copy-Item -Force (Join-Path $root "capstone\lib\$capstoneName") (Join-Path $libDir $capstoneName)
