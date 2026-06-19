# Evasion Framework

12 modules implementing documented real-world anti-analysis techniques. Each module is independently testable and maps to a specific MITRE ATT&CK technique. Every module also has a corresponding detection rule in [`detection-rules/`](../detection-rules/).

---

## Modules

| Module | Technique | ATT&CK | What It Does |
|---|---|---|---|
| `anti_vm` | VM detection | T1497.001 | CPUID hypervisor bit, DMI product strings, MAC address OUI checks, timing differentials |
| `anti_debug` | Debugger detection | T1622 | `ptrace(PTRACE_TRACEME)` self-attach, RDTSC timing attacks, `/proc/self/status` TracerPid check |
| `process_hollowing` | Process injection | T1055.012 | Suspend target → unmap memory → inject payload → resume |
| `api_unhooking` | EDR hook removal | T1562.001 | Load a fresh copy of `ntdll.dll` from disk to bypass in-memory EDR hooks |
| `amsi_bypass` | AMSI evasion | T1562.001 | Patches AMSI scan result in memory to always return clean |
| `memory_exec` | In-memory execution | T1055 | Maps and executes shellcode without touching disk |
| `memory_scrambler` | String obfuscation | T1027 | XOR-obfuscates strings in memory; decoded only at point of use |
| `protocol_tunnel` | Covert channels | T1572 | DNS, ICMP, and HTTP tunneling for C2 fallback communication |
| `uefi_rootkit` | UEFI persistence | T1542.003 | UEFI variable manipulation for pre-boot persistence (research only) |
| `reflective_dll` | DLL injection | T1620 | Loads a DLL from memory without a disk write or standard loader |
| `dropper` | Payload delivery | T1204 | Simulates staged payload delivery via fake download |
| `orchestrator` | Coordination | - | Selects and sequences techniques based on environment fingerprint |

---

## VM Detection Detail

The `anti_vm` module runs a sequence of checks before the payload executes:

**CPUID hypervisor bit** - `CPUID` with `EAX=1` returns bit 31 of `ECX` set in all major hypervisors. Bare metal always returns 0.

**Hypervisor vendor string** - `CPUID` with `EAX=0x40000000` returns a 12-byte vendor string:
- VMware: `VMwareVMware`
- VirtualBox: `VBoxVBoxVBox`
- Hyper-V: `Microsoft Hv`
- KVM: `KVMKVMKVM`

**DMI strings** - `/sys/class/dmi/id/product_name` and `sys_vendor` contain `VirtualBox`, `VMware`, or `QEMU` on virtual machines.

**Timing** - RDTSC reads inside a VM show artificially consistent intervals compared to the noise of physical hardware.

If any check triggers, the simulator exits cleanly rather than proceeding with encryption. This is standard behavior in real malware - avoiding sandbox detonation.

---

## Anti-Debug Detail

**ptrace self-attach** - a process that calls `ptrace(PTRACE_TRACEME, 0, NULL, NULL)` prevents any external debugger from attaching. If a debugger is already attached, the call fails, signaling that the process is being analyzed.

**RDTSC timing** - measures the time between two RDTSC reads around a short NOP sled. Under a debugger, the interval is orders of magnitude longer. The simulator uses a threshold of ~1000 cycles; typical debugger overhead is 10,000-100,000 cycles.

**TracerPid check** - on Linux, `/proc/self/status` exposes `TracerPid`. A non-zero value means a debugger is attached.

---

## MITRE ATT&CK Coverage

The evasion framework covers techniques across three tactics:

| Tactic | Techniques |
|---|---|
| Defense Evasion | T1497.001, T1622, T1055.012, T1562.001, T1027, T1572, T1055, T1620 |
| Persistence | T1542.003 |
| Execution | T1204, T1055 |
