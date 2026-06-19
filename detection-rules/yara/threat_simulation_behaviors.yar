/*
 * YARA Detection Rules — Threat Simulation Capstone
 *
 * These rules detect behavioral patterns exhibited by the simulation.
 * They are designed for blue team training and SIEM/EDR integration.
 *
 * References: MITRE ATT&CK T1486, T1027, T1055, T1497, T1622, T1572
 */

rule FileEncryptionRapidModification
{
    meta:
        description = "Detects rapid sequential file modification typical of encryption operations"
        author      = "Threat Simulation Capstone — Detection Engineering"
        reference   = "MITRE ATT&CK T1486"
        severity    = "HIGH"

    strings:
        $encrypted_ext_1 = ".encrypted" ascii nocase
        $encrypted_ext_2 = ".locked"    ascii nocase
        $encrypted_ext_3 = ".enc"       ascii nocase

    condition:
        any of ($encrypted_ext_*)
}

rule HybridEncryptionHeader
{
    meta:
        description     = "Detects RSA-wrapped AES key header prepended to encrypted files"
        author          = "Threat Simulation Capstone — Detection Engineering"
        reference       = "MITRE ATT&CK T1486"
        severity        = "HIGH"

    strings:
        /*
         * RSA-2048 OAEP wrapped key: 256-byte block at file start
         * followed by 12-byte GCM nonce (pattern matches simulation output format)
         */
        $rsa_key_header = { [256] [12] }

    condition:
        $rsa_key_header at 0
}

rule C2RegistrationPattern
{
    meta:
        description = "Detects C2 registration HTTP pattern in process memory or network captures"
        author      = "Threat Simulation Capstone — Detection Engineering"
        reference   = "MITRE ATT&CK T1071.001"
        severity    = "HIGH"

    strings:
        $api_register   = "/api/register"    ascii
        $api_exfil      = "/api/exfiltrate"  ascii
        $api_command    = "/api/command"     ascii
        $victim_id_key  = "victim_id"        ascii

    condition:
        2 of ($api_*) or $victim_id_key
}

rule SecureMemoryWipePattern
{
    meta:
        description = "Detects OPENSSL_cleanse or ZeroMemory patterns indicating key material destruction"
        author      = "Threat Simulation Capstone — Detection Engineering"
        reference   = "MITRE ATT&CK T1027"
        severity    = "MEDIUM"

    strings:
        $openssl_cleanse = "OPENSSL_cleanse" ascii
        $zero_memory     = "ZeroMemory"      ascii
        $secure_zero     = "SecureZeroMemory" ascii
        $explicit_bzero  = "explicit_bzero"  ascii

    condition:
        any of them
}

rule AntiVMCPUID
{
    meta:
        description = "Detects CPUID-based VM fingerprinting (VMware, VirtualBox, Hyper-V)"
        author      = "Threat Simulation Capstone — Detection Engineering"
        reference   = "MITRE ATT&CK T1497.001"
        severity    = "MEDIUM"

    strings:
        $vmware_str  = "VMwareVMware" ascii
        $vbox_str    = "VBoxVBoxVBox" ascii
        $hyperv_str  = "Microsoft Hv" ascii
        $kvm_str     = "KVMKVMKVM"   ascii

    condition:
        any of them
}

rule ProcessHollowingIndicator
{
    meta:
        description = "Detects process hollowing pattern: ZwUnmapViewOfSection + WriteProcessMemory sequence"
        author      = "Threat Simulation Capstone — Detection Engineering"
        reference   = "MITRE ATT&CK T1055.012"
        severity    = "HIGH"

    strings:
        $unmap    = "ZwUnmapViewOfSection"  ascii
        $write_pm = "WriteProcessMemory"    ascii
        $resume   = "ResumeThread"          ascii

    condition:
        all of them
}

rule RansomNoteCreation
{
    meta:
        description = "Detects creation of ransom note files by common naming convention"
        author      = "Threat Simulation Capstone — Detection Engineering"
        reference   = "MITRE ATT&CK T1486"
        severity    = "HIGH"

    strings:
        $note_1 = "README_DECRYPT"    ascii nocase
        $note_2 = "HOW_TO_DECRYPT"    ascii nocase
        $note_3 = "RECOVER_FILES"     ascii nocase
        $note_4 = "YOUR_FILES"        ascii nocase
        $note_5 = "RANSOM_NOTE"       ascii nocase

    condition:
        any of them
}
