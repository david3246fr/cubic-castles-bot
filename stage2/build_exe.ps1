# Build the Cubic Castles bot into single double-clickable .exe files.
#
# Produces TWO exes from ONE codebase (the GUI picks its mode from the exe's
# own filename):
#   dist\cubic-bot.exe        SIMPLE  — the small one (Logs / Market / Scan / Status)
#   dist\cubic-bot-full.exe   FULL    — every feature; adds a Controls tab
#                                       (Teleport + Park realm + Help/Where/
#                                        Park now/Players/Friends)
#
# NOTHING account-specific is baked in. First run captures the login of whoever
# runs it (Set up login -> attach to the game -> log in) and saves it to
# %APPDATA%\CubicBot; every later run just uses it. The capture agent
# (nopoll_agent.js) and the Frida runtime are baked in; the machine still needs
# Cubic Castles installed + running via Steam for the one-time setup.
#
#   From this stage2 folder, run:  .\build_exe.ps1
#   (add  -Only simple   or   -Only full   to build just one)

param([ValidateSet("both", "simple", "full")] [string]$Only = "both")

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$agent = "nopoll_agent.js"
if (-not (Test-Path $agent)) {
    Write-Error "Missing $agent -- the capture agent must sit next to this script."
}

Write-Host "Ensuring build deps (pyinstaller, websocket-client, frida)..." -ForegroundColor Cyan
python -m pip install --quiet --upgrade pyinstaller websocket-client frida
if (-not $?) { Write-Error "pip install failed" }

# Clean previous build so a stale bundle never ships.
foreach ($d in @("build", "dist", "__pycache__")) {
    if (Test-Path $d) { Remove-Item -Recurse -Force $d }
}
Get-ChildItem -Filter "cubic-bot*.spec" -ErrorAction SilentlyContinue | Remove-Item -Force

function Build-One([string]$name, [bool]$simple) {
    Write-Host "Building $name.exe (this takes a minute or two)..." -ForegroundColor Cyan
    $pyArgs = @(
        "--onefile", "--windowed", "--name", $name,
        "--add-data", "$agent;.",
        "--collect-all", "frida",
        "--hidden-import", "websocket",
        "--hidden-import", "cc_protocol",
        "--hidden-import", "send_cipher",
        "--hidden-import", "xxtea",
        "--hidden-import", "cc_storage",
        "--hidden-import", "cc_orders",
        "--hidden-import", "cc_provision",
        "--hidden-import", "cc_remote",
        "--hidden-import", "cc_gui",
        "--hidden-import", "cc_client"
    )
    if ($simple) {
        # SIMPLE build = core features only (teleport/nav, guid, vend/market,
        # Discord). The bot is launched with --simple so it REFUSES every other
        # command; on top of that we keep the extra-feature modules — and their
        # heavy ML deps (torch/argostranslate/etc. via the translator) — OUT of
        # the binary entirely, so the simple exe stays small.
        foreach ($m in @("cc_translate", "cc_quiz", "cc_builder", "cc_live_builder",
                         "argostranslate", "ctranslate2", "torch", "langdetect",
                         "spacy", "stanza", "sacremoses", "scipy", "pandas",
                         "numba", "llvmlite", "sympy", "matplotlib", "onnxruntime",
                         "tensorflow", "sklearn", "IPython", "jedi")) {
            $pyArgs += @("--exclude-module", $m)
        }
    } else {
        # FULL build bundles the quiz brain; the translator/builder are optional
        # and get pulled in automatically when their deps are installed locally.
        $pyArgs += @("--hidden-import", "cc_quiz")
    }
    $pyArgs += "cc_bot_launcher.py"
    python -m PyInstaller @pyArgs
    if (-not $?) { Write-Error "PyInstaller build failed for $name" }
}

if ($Only -eq "both" -or $Only -eq "simple") { Build-One "cubic-bot" $true }
if ($Only -eq "both" -or $Only -eq "full")   { Build-One "cubic-bot-full" $false }

Write-Host ""
Write-Host "Done. In $(Join-Path $PSScriptRoot 'dist'):" -ForegroundColor Green
if ($Only -ne "full")   { Write-Host "  cubic-bot.exe        (SIMPLE - the small one)" -ForegroundColor Green }
if ($Only -ne "simple") { Write-Host "  cubic-bot-full.exe   (FULL - every feature)" -ForegroundColor Green }
