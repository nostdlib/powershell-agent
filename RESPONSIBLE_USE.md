# Responsible Use Policy

## Purpose

powershell-agent is developed and maintained for the following legitimate purposes:

- **Education** -- Studying PowerShell host internals (Windows PowerShell 2.0+ compat), .NET in-process deserialization surfaces, HTTP command-and-control protocol design, and defensive detection engineering against script-host implants
- **Authorized Security Testing** -- Supporting professional penetration testers and red team operators who hold explicit written authorization from the system owner to conduct security assessments
- **Capture The Flag (CTF) Competitions** -- Providing a reference for techniques commonly encountered in offensive security competitions held in controlled, sanctioned environments
- **Academic and Independent Research** -- Enabling security researchers to study, document, and develop defenses against real-world offensive techniques in a transparent, open-source context

Detection engineering against this agent should start with [DEFENSE.md](DEFENSE.md).

## Prohibited Uses

The following uses of this software are strictly prohibited:

- **Unauthorized access** -- Deploying powershell-agent against any system, network, or environment without explicit written authorization from the owner or authorized representative
- **Malware development or distribution** -- Using powershell-agent code or techniques to create, package, or distribute malicious software intended to harm individuals, organizations, or infrastructure
- **Data theft or exfiltration** -- Using powershell-agent to steal, collect, or exfiltrate personal data, credentials, intellectual property, or any information without authorization
- **Denial of service** -- Using powershell-agent to disrupt, degrade, or deny availability of systems, services, or networks
- **Evasion of lawful security controls** -- Using powershell-agent to circumvent security measures on systems you are not authorized to test
- **Surveillance** -- Using powershell-agent to monitor, track, or surveil individuals without proper legal authority and consent
- **Commercial exploitation without compliance** -- Redistributing or using powershell-agent in violation of the MIT license terms

## User Responsibility

By using this software, you acknowledge and agree to the following:

1. **Authorization** -- You will only deploy powershell-agent in environments where you have obtained explicit written authorization from the system owner or an authorized representative. Verbal agreements are insufficient.
2. **Compliance** -- You are responsible for compliance with all applicable local, national, and international laws, including computer misuse, data protection, and privacy statutes.
3. **Liability** -- The authors and contributors accept no liability for misuse. The burden of lawful, ethical use rests entirely with the operator.
4. **Disclosure** -- If you discover the agent being used maliciously, report it through appropriate incident-response channels.

## See Also

- [SECURITY.md](SECURITY.md) -- vulnerability reporting
- [DEFENSE.md](DEFENSE.md) -- detection guidance
