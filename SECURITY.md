# Security Policy

## Responsible Use

powershell-agent is designed for **legitimate security research, authorized penetration testing, and
educational purposes**. Users must ensure they have proper authorization before deploying it in
any environment. See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md).

## Supported Versions

Security updates are applied to the latest version on the `main` branch only. We do not maintain
separate release branches at this time.

| Version | Supported |
|---------|-----------|
| `main` (latest) | Yes |
| Older commits | No |

## Reporting a Vulnerability

Please report vulnerabilities by opening a GitHub security advisory or contacting the maintainer
directly. Include:

- A description of the issue and its impact
- Steps or proof-of-concept to reproduce
- Affected file(s) and line references

We will acknowledge reports and keep the reporter informed of remediation progress. Researchers
acting in good faith will not face legal action for work that stays within authorized scopes
(e.g. the repository itself).

## Scope Notes

- The agent intentionally performs insecure operations (in-process `BinaryFormatter`
  deserialization, TLS 1.2 negotiation, machine-identity reads). These are its documented,
  researched behavior -- not vulnerabilities to report.
- Vulnerabilities in the DEFENSE.md detection guidance (missed indicators) are in scope and
  welcome.
