# Research & Findings

The `research/` module treats the simulator as a measurement instrument. Every run produces exportable data - CSV, JSON, LaTeX tables, Markdown. The goal was to answer concrete questions about detection windows, technique coverage, and which defensive controls actually work against modern encryption-based attacks.

---

## Ransomware Family Comparison

Technique coverage measured against 10 documented ransomware families using Jaccard similarity on their MITRE ATT&CK technique sets. Data sourced from CISA advisories, FBI flash reports, and published threat intelligence.

| Family | Symmetric | Asymmetric | Jaccard Similarity |
|---|---|---|---|
| LockBit 3.0 | AES-256 | RSA-2048 | 0.85 |
| BlackCat/ALPHV | ChaCha20 | RSA-4096 | 0.80 |
| REvil/Sodinokibi | Salsa20 | Curve25519 | 0.78 |
| Conti | AES-256 | RSA-4096 | 0.75 |
| Ryuk | AES-256 | RSA-4096 | 0.71 |
| DarkSide | Salsa20 | RSA-1024 | 0.68 |
| Maze | ChaCha | RSA-2048 | 0.66 |
| Hive | ChaCha20 | RSA-3072 | 0.63 |
| BlackBasta | ChaCha20 | RSA-4096 | 0.61 |
| Royal | AES-256 | RSA-4096 | 0.59 |

Highest similarity with LockBit 3.0 was expected - the intermittent encryption mode and evasion technique selection were specifically modeled after published LockBit 3.0 analysis.

---

## Detection Effectiveness

The `DetectionAnalyzer` class runs the simulator against each detection type and records true positives, false positives, detection latency, and computes F1 and Matthews Correlation Coefficient (MCC).

| Detection Type | Detection Rate | False Positive Rate | F1 | Notes |
|---|---|---|---|---|
| YARA static | 0.91 | 0.04 | 0.93 | Highest accuracy; binary patterns don't drift |
| Sigma / SIEM | 0.85 | 0.08 | 0.87 | Dependent on log completeness |
| EDR behavioral | 0.78 | 0.12 | 0.82 | Drops significantly with intermittent encryption |
| Network monitoring | 0.72 | 0.15 | 0.76 | C2 on loopback limits signal; tunneling evades further |

**Key finding** - EDR behavioral detection rate drops when `INTERMITTENT` mode is enabled. Rules tuned for "X file modifications per minute" miss encryption events that are spread across longer windows with lower CPU utilization. YARA holds up because it operates on file content regardless of timing.

---

## Encryption Benchmarks

Run against 180 test files (100 documents, 50 images, 10 databases, 20 archives).

| Mode | Avg Time | CPU Peak | Detection Window |
|---|---|---|---|
| `FULL` | ~120s | 85% | Wide - sustained high CPU |
| `HEADER_ONLY` | ~8s | 40% | Narrow - hard to catch |
| `INTERMITTENT` | ~45s | 30% | Narrow - behavioral rules miss it |

`HEADER_ONLY` is the fastest and most evasive for small to medium files. `INTERMITTENT` is optimized for large files where full encryption would take too long and trigger time-based detections.

---

## Metrics Collection

The `MetricsCollector` class records observations during runs and produces statistical summaries.

Outputs per run:
- Mean, median, standard deviation, min, max, P95 for any recorded metric
- 95% confidence intervals
- Experiment results across N iterations with configurable warmup
- Export to: CSV, JSON, LaTeX, Markdown, Mermaid/D3.js visualizations

---

## Research Questions Addressed

**Q: How does intermittent encryption affect behavioral detection rates?**
EDR detection rate drops from 0.78 to approximately 0.51 in `INTERMITTENT` mode. Behavioral rules calibrated on full-encryption timing patterns produce a significant gap.

**Q: What is the minimum encryption ratio needed to make a file unrecoverable?**
`HEADER_ONLY` (encrypting first 4MB) renders all test file types unreadable. Image viewers, document editors, and database engines all fail to open partially encrypted files.

**Q: Which detection control offers the best coverage/noise trade-off?**
YARA static analysis - highest detection rate (0.91), lowest false positive rate (0.04). The trade-off is that it requires a file to land on disk or memory to be scanned, whereas network monitoring catches C2 traffic earlier in the chain.
