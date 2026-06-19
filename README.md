# Threat Simulation Capstone

Professional-grade adversary simulation built for CSCI 460. Implements the full ransomware attack chain - hybrid cryptography, C2 infrastructure, evasion, and privilege escalation - isolated inside Docker, with a blue team detection framework that treats defense as a first-class deliverable.

---

This started as a class project. After my midterm presentation the questions kept coming back to how real threat actors operate at scale, so I rebuilt it from scratch - cross-platform C++17, real C2 infrastructure, LockBit 3.0-style intermittent encryption, a full evasion framework, and a research layer that benchmarks the simulator against documented ransomware families. The blue team side is not an afterthought. Every offensive technique has a corresponding YARA rule, Sigma rule, MITRE ATT&CK mapping, and detection effectiveness measurement.

---

## Documentation

| Section | Description |
|---|---|
| [Architecture](docs/architecture.md) | System design, isolation model, component overview |
| [Cryptography](docs/cryptography.md) | Hybrid RSA-2048 + AES-256-GCM design and key management |
| [Evasion Framework](docs/evasion.md) | 12 anti-analysis modules with ATT&CK mappings |
| [Research & Findings](docs/research.md) | Ransomware family comparison, detection effectiveness metrics |
| [Detection Engineering](docs/detection.md) | YARA rules, Sigma rules, detection strategy |

Detection rules are in [`detection-rules/`](detection-rules/) - no code access required.

---

## Code Access

Source code (simulator, C2 server, exploit modules, Docker environment) is not publicly distributed. Available to vetted researchers and security students with a legitimate use case.

Email **aimery@barratec.com** - include your name, affiliation, and intended use. I'll review and add you as a collaborator on the private repository.

---

## Legal

MIT License - educational use only. Unauthorized use outside isolated lab environments may violate the Computer Fraud and Abuse Act (CFAA) and equivalent international law.
