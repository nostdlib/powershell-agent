# Defense Guide: powershell-agent

Detection guidance for defenders facing this agent, derived from its source
([`src/powershell-agent.ps1`](src/powershell-agent.ps1)). Everything below is observable; nothing
here is a bypass technique.

## Network indicators

- **Transport**: plain `HttpWebRequest` POSTs to one endpoint (`H_URL`) on a repeating cadence —
  an immediate re-POST after every empty answer, so the flow is a steady request train rather
  than jittered polling. Each request carries:
  - `Content-Type: application/octet-stream`
  - The full identity header set (API 1): `X-Device-Id`, `X-Session-Id`,
    `X-Device-Name`,
    `X-User-Id`, `X-Device-Arch`, `X-App-Arch`, `X-Platform: Windows`,
    `X-OS-Version`, `X-OS-Build`, `X-Client-Id: 3`,
    `X-Client-Features: 0800000000000000` — a header cluster no legitimate software emits
    (detection-derived members are omitted when undetectable; there is no bitness header —
    the process arch carries the full width).
    **Any one of these on an internal POST is a high-confidence signature**; see the relay
    protocol docs for the full header semantics.
  - Log ships are the same POST with `X-Log-Only: 1`.
- **Body shape**: raw binary `[u32le length][bytes]` frames (v3). Small bodies (0–12 bytes for
  command replies) and Content-Length bodies that don't parse as text.

A Suricata rule keyed on the header cluster (`http.header; content:"X-Client-Features"`,
paired with `X-Client-Id: 3`) on egress covers the whole agent family with breed
disambiguation for free.

## Host indicators

- **Host process**: always `powershell.exe` (2.0–5.1; PS 7+ cannot run the deserialization arm).
  Delivery one-liners to hunt: `irm <url> | iex`, `(New-Object Net.WebClient).DownloadString`,
  `-EncodedCommand` in a relaunching host, `-WindowStyle Hidden`.
- **ScriptBlock Logging (Event ID 4104)**: the agent core is pure script — `Invoke-Agent`,
  `DispatchCommand`, `BuildIdentity`, the identity header names, and the
  `System.Runtime.Serialization.Formatters.Binary.BinaryFormatter` instantiation all appear in
  script-block text when logging is enabled. Module logging and transcription capture the same.
  **Obfuscated builds** (the C2 panel's shipped form) change what text is observable: names are
  randomized, comments stripped, and every string literal — the WMI class names, the header
  names, the serde-chain names — is rewritten as runtime-assembled `(-join[char[]](…))` joins,
  so those tokens never exist in the file, in the AMSI buffer, or in the 4104 text. What
  remains observable is the structural layer: `New-Object`, `[wmiclass]`, `[Net.*]` type
  accelerators, and member names — structure-anchored hunts still land; text hunts don't.
- **AMSI**: the agent text and its host master pass through AMSI on Windows 10+ — an AMSI-aware
  EDR sees the full source before execution.
- **Environment**: the beacon endpoint is set as the process env var `H_URL` before the agent
  runs; the upgrade arm sets `COMPLUS_Version` (`v2.0.50727`/`v4.0.30319`) and arbitrary
  `NAME=value` process env vars.
- **Identity reads**: `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` (directly and via WMI
  `StdRegProv`), `Win32_ComputerSystemProduct.UUID`, `Win32_OperatingSystem`,
  `Win32_Processor` — a WMI query cluster characteristic of implant fingerprinting. In
  obfuscated builds the class names travel as encoded string data, so the cluster shows in
  behavior and WMI-activity ETW, not in file or script-block text.
- **In-process deserialization** (UpgradeNetFramework): `BinaryFormatter.Deserialize` on a
  `MemoryStream` inside powershell.exe — watch for .NET serialization ETW/events and
  `COMPLUS_Version` being set.

## MITRE ATT&CK mapping

| Technique | How it appears here |
|---|---|
| T1059.001 Command & Scripting Interpreter: PowerShell | The agent is PowerShell script, hosted in powershell.exe |
| T1071.001 Application Layer Protocol: Web | Long-poll HTTP beaconing with binary frames |
| T1041 Exfiltration over C2 Channel | Reply frames on the beacon POST |
| T1547 / T1053 (host-side) | The C2 host master is commonly delivered by on-logon persistence; the agent itself persists nothing |
| T1036 Masquerading | identity header names mimic telemetry-client vocabulary (`X-Device-Id` et al.), but the fixed set + constants remain a trivially correlatable signature (by design) |

## Why publish this?

The agent is deliberately detectable: fixed header names, fixed capabilities string, fixed
framing, and script-block-visible source. Publishing the detection surface alongside the source
keeps the research usable for both sides.
