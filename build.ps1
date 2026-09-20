# build.ps1 — the flavor split: the "#if DEBUG" analog (PowerShell has no preprocessor,
# so the marker is a LINE TAG). Source lines ending in a #dbg comment exist ONLY in the
# debug build:
#   dist/powershell-agent.ps1        release — every tagged line REMOVED (zero diagnostics)
#   dist-debug/powershell-agent.ps1  debug   — tagged lines kept, the tag suffix dropped
# The tag is the flavor: CI publishes dist/ to the rolling 'release' tag and
# dist-debug/ to the rolling 'debug' tag (same asset filename — the tag, not
# the filename, carries the flavor). Gates (the build FAILS, not warns): both flavors
# keep the fetch-contract needle and parse clean; the release flavor carries none of the
# debug surface (the popup helper's tokens) and no leftover tag suffix.

param([string]$Source = (Join-Path $PSScriptRoot 'src/powershell-agent.ps1'))

$ErrorActionPreference = 'Stop'
$lines = [IO.File]::ReadAllLines($Source)
$release = New-Object 'System.Collections.Generic.List[string]'
$debug = New-Object 'System.Collections.Generic.List[string]'
foreach ($line in $lines) {
    # The tag is ' #dbg' at end-of-line (trailing whitespace allowed). A tag ANYWHERE
    # else — mid-line, misspelled, text after it — is NOT a tag: the line stays in the
    # release flavor and the release gate below fails the build loudly instead of a
    # silent diagnostic leak.
    if ($line -match '^(.*?)\s#dbg\s*$') { $debug.Add($Matches[1]) }
    else { $release.Add($line); $debug.Add($line) }
}
$releaseText = ($release -join "`r`n") + "`r`n"
$debugText = ($debug -join "`r`n") + "`r`n"

# ── gates ─────────────────────────────────────────────────────────
# Both flavors ship through AgentBinaryService.LooksLikePowerShellAgent — keep the needle.
foreach ($t in @('release', 'debug')) {
    $text = if ($t -eq 'release') { $releaseText } else { $debugText }
    if ($text -notmatch 'function Invoke-Agent') { throw "$t flavor lost the 'function Invoke-Agent' contract needle" }
    if ($text.Length -le 200) { throw "$t flavor too short ($($text.Length) chars)" }
    $errs = $null
    [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$errs) | Out-Null
    if ($errs -and $errs.Count -gt 0) {
        $errs | ForEach-Object { Write-Host ("$t PARSE ERROR line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) }
        throw "$t flavor does not parse"
    }
}
# Release carries ZERO debug surface: the popup helper's tokens, its caption prefix, any
# leftover tag suffix, any un-tagged debug-helper call that slipped the marker.
foreach ($t in @('WScript.Shell', 'Popup', 'ps-agent dbg')) {
    if ($releaseText.Contains($t)) { throw "release flavor carries debug surface: '$t'" }
}
if ($releaseText -match '(?m)^.*\s#dbg\s*$') { throw 'release flavor carries a leftover #dbg-tagged line' }
if ($releaseText -cmatch '(?<![.\w-])Dbg\s') { throw "release flavor references the debug helper (an un-tagged call slipped the marker?)" }

# ── write ─────────────────────────────────────────────────────────
$dist = Join-Path $PSScriptRoot 'dist'
$distDebug = Join-Path $PSScriptRoot 'dist-debug'
New-Item -ItemType Directory -Force $dist | Out-Null
New-Item -ItemType Directory -Force $distDebug | Out-Null
[IO.File]::WriteAllText((Join-Path $dist 'powershell-agent.ps1'), $releaseText)
[IO.File]::WriteAllText((Join-Path $distDebug 'powershell-agent.ps1'), $debugText)
Write-Host ("OK  release {0} -> dist/powershell-agent.ps1 ({1} lines)" -f $Source, $release.Count)
Write-Host ("OK  debug   {0} -> dist-debug/powershell-agent.ps1 ({1} lines, {2} tagged lines)" -f $Source, $debug.Count, ($lines.Count - $release.Count))
