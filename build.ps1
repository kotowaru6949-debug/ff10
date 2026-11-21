$ErrorActionPreference = "Stop"

$cscPath = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if (-not (Test-Path $cscPath)) {
    throw "csc.exe not found at $cscPath"
}

$srcFile = Join-Path $PSScriptRoot "src\FFXComfortTool.cs"
$outFile = Join-Path $PSScriptRoot "FFXComfortTool.exe"

Write-Host "Building $outFile ..."
& $cscPath /nologo /target:winexe /platform:x86 /optimize+ /warnaserror+ "/out:$outFile" $srcFile
if ($LASTEXITCODE -ne 0) {
    throw "Build failed with exit code $LASTEXITCODE"
}

Write-Host "Build succeeded: $outFile"
