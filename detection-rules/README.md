# Detection Rules

YARA signatures and Sigma rules developed alongside the threat simulation to enable blue team detection of the simulated attack chain.

## YARA Rules

`yara/threat_simulation_behaviors.yar` covers:

| Rule | Technique | ATT&CK ID |
|---|---|---|
| `FileEncryptionRapidModification` | Encrypted file extension detection | T1486 |
| `HybridEncryptionHeader` | RSA-wrapped AES header in encrypted files | T1486 |
| `C2RegistrationPattern` | C2 API endpoint strings in memory/network | T1071.001 |
| `SecureMemoryWipePattern` | Key material destruction (OPENSSL_cleanse) | T1027 |
| `AntiVMCPUID` | CPUID-based hypervisor fingerprinting | T1497.001 |
| `ProcessHollowingIndicator` | ZwUnmapViewOfSection + WriteProcessMemory | T1055.012 |
| `RansomNoteCreation` | Common ransom note filename patterns | T1486 |

Run with:
```bash
yara -r yara/threat_simulation_behaviors.yar /path/to/scan
```

## Sigma Rules

`sigma/file_encryption_activity.yml` covers multiple rules in one file:

| Rule | Technique | Level |
|---|---|---|
| Rapid File Encryption Activity | T1486 | High |
| C2 Registration API Call | T1071.001 | Medium |
| Anti-Debug ptrace Attempt | T1622 | Low |
| Privilege Escalation via SUID Binary | T1068 | High |
| Key Exfiltration HTTP POST | T1041 | High |

Convert to your SIEM with sigmac:
```bash
sigmac -t splunk sigma/file_encryption_activity.yml
sigmac -t elastic sigma/file_encryption_activity.yml
sigmac -t qradar sigma/file_encryption_activity.yml
```

## Notes

- All rules are experimental and tuned for the simulation environment. Adjust thresholds for production use.
- False positive guidance is included per rule.
- Rules reflect the full attack chain: initial execution → encryption → exfiltration → C2 polling.
