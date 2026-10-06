$ErrorActionPreference = 'Stop'
$taskRoot = $PSScriptRoot
$taskBundledPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
if (Test-Path -LiteralPath $taskBundledPython) {
    $taskPython = $taskBundledPython
} else {
    $taskPython = (Get-Command python -ErrorAction Stop).Source
}
Push-Location -LiteralPath $taskRoot
try {
    if (-not (Test-Path -LiteralPath 'node_modules')) {
        & npm.cmd ci
        if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
    }
    & $taskPython -c 'import requests'
    if ($LASTEXITCODE -ne 0) {
        & $taskPython -m pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed.' }
    }
    & npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw 'The application build failed.' }
    & $taskPython scripts/local_app.py
    if ($LASTEXITCODE -ne 0) { throw 'The local application stopped with an error.' }
} finally {
    Pop-Location
}
