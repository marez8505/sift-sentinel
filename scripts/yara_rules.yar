/*
 * SIFT Sentinel YARA Rules
 * Starter ruleset for autonomous threat hunting on SIFT workstation.
 * These rules are designed to complement Volatility analysis and disk triage.
 *
 * Categories:
 *   - Masquerading (binaries using legitimate names in wrong locations)
 *   - Common C2 patterns (Cobalt Strike, Meterpreter, PowerShell loaders)
 *   - LOLBin abuse (certutil, mshta, regsvr32, rundll32 with suspicious args)
 *   - Credential theft tools (mimikatz variants)
 *   - Persistence mechanisms (scheduled task XML, WMI subscriptions)
 *   - PowerShell encoded command patterns
 */

import "pe"
import "math"

// ---------------------------------------------------------------------------
// Masquerading
// ---------------------------------------------------------------------------

rule Masquerade_System32_Executable
{
    meta:
        description = "PE binary in a temp or user directory masquerading as a System32 process name"
        author = "SIFT Sentinel"
        severity = "high"
        mitre = "T1036.005"

    strings:
        $s1 = "svchost.exe" nocase wide ascii
        $s2 = "lsass.exe"   nocase wide ascii
        $s3 = "csrss.exe"   nocase wide ascii
        $s4 = "winlogon.exe" nocase wide ascii
        $s5 = "explorer.exe" nocase wide ascii
        $s6 = "services.exe" nocase wide ascii
        $s7 = "smss.exe"    nocase wide ascii
        $s8 = "wininit.exe" nocase wide ascii
        $s9 = "taskhost.exe" nocase wide ascii
        $s10 = "taskhostw.exe" nocase wide ascii
        $s11 = "spoolsv.exe" nocase wide ascii
        $s12 = "dllhost.exe" nocase wide ascii
        $s13 = "conhost.exe" nocase wide ascii

    condition:
        uint16(0) == 0x5A4D and
        any of ($s*) and
        not pe.is_32bit() == false  // heuristic placeholder — combine with path check
}

rule Binary_In_Temp_Or_AppData
{
    meta:
        description = "PE binary with path strings indicating execution from Temp or AppData"
        author = "SIFT Sentinel"
        severity = "medium"
        mitre = "T1036"

    strings:
        $p1 = "\\Temp\\" nocase wide
        $p2 = "\\AppData\\Local\\Temp\\" nocase wide
        $p3 = "\\AppData\\Roaming\\" nocase wide
        $p4 = "\\Users\\Public\\" nocase wide
        $p5 = "\\ProgramData\\" nocase wide

    condition:
        uint16(0) == 0x5A4D and
        any of ($p*)
}

// ---------------------------------------------------------------------------
// Cobalt Strike
// ---------------------------------------------------------------------------

rule CobaltStrike_Beacon_Config
{
    meta:
        description = "Cobalt Strike beacon configuration block"
        author = "SIFT Sentinel"
        severity = "critical"
        mitre = "T1055, T1095"
        reference = "https://github.com/dcsync/pycobalt"

    strings:
        // Beacon config magic bytes (XOR key 0x69 pattern)
        $magic1 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }
        // Common beacon strings
        $s1 = "%s (admin)" wide ascii
        $s2 = "beacon.x64.dll" nocase
        $s3 = "beacon.dll" nocase
        $s4 = "ReflectiveLoader" ascii
        // Sleep mask
        $sleep = { 48 B9 ?? ?? ?? ?? ?? ?? ?? ?? 48 31 08 }

    condition:
        any of them
}

rule CobaltStrike_Malleable_C2_Pipe
{
    meta:
        description = "Cobalt Strike SMB named pipe patterns used in lateral movement"
        author = "SIFT Sentinel"
        severity = "critical"
        mitre = "T1021.002"

    strings:
        $p1 = "\\\\.\\pipe\\MSSE-" wide ascii
        $p2 = "\\\\.\\pipe\\msagent_" wide ascii
        $p3 = "\\\\.\\pipe\\postex_" wide ascii
        $p4 = "\\\\.\\pipe\\status_" wide ascii
        $p5 = "\\\\.\\pipe\\interop_" wide ascii
        $p6 = "\\\\.\\pipe\\dce_" wide ascii

    condition:
        any of ($p*)
}

// ---------------------------------------------------------------------------
// Meterpreter / Metasploit
// ---------------------------------------------------------------------------

rule Meterpreter_Reflective_DLL
{
    meta:
        description = "Meterpreter reflective DLL injection artifact"
        author = "SIFT Sentinel"
        severity = "critical"
        mitre = "T1055.001"

    strings:
        $r1 = "ReflectiveLoader" fullword ascii
        $r2 = "metsrv" ascii nocase
        $r3 = "meterpreter" ascii nocase
        $r4 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }

    condition:
        $r1 or ($r2 and $r3) or ($r4 and ($r2 or $r3))
}

// ---------------------------------------------------------------------------
// Mimikatz / Credential Theft
// ---------------------------------------------------------------------------

rule Mimikatz_Generic
{
    meta:
        description = "Mimikatz credential theft tool or variant"
        author = "SIFT Sentinel"
        severity = "critical"
        mitre = "T1003.001"

    strings:
        $s1 = "mimikatz" nocase ascii wide
        $s2 = "sekurlsa" nocase ascii wide
        $s3 = "lsadump" nocase ascii wide
        $s4 = "kerberos::golden" nocase ascii wide
        $s5 = "privilege::debug" nocase ascii wide
        $s6 = "Benjamin DELPY" nocase
        $s7 = "gentilkiwi" nocase
        $w1 = "wdigest.dll" nocase wide
        $w2 = "kerberos.dll" nocase wide

    condition:
        2 of them
}

rule Credential_Dumping_LSASS
{
    meta:
        description = "Attempt to dump LSASS process memory"
        author = "SIFT Sentinel"
        severity = "critical"
        mitre = "T1003.001"

    strings:
        $s1 = "lsass.dmp" nocase ascii wide
        $s2 = "lsass.exe" nocase wide
        $s3 = "MiniDumpWriteDump" ascii
        $s4 = "OpenProcess" ascii
        $s5 = "procdump" nocase ascii wide
        $combo1 = "lsass" nocase
        $combo2 = "MiniDump" nocase

    condition:
        ($s1 or ($combo1 and $combo2)) or ($s3 and $s4 and $s5)
}

// ---------------------------------------------------------------------------
// PowerShell Abuse
// ---------------------------------------------------------------------------

rule PowerShell_Encoded_Command
{
    meta:
        description = "PowerShell encoded command (-enc / -EncodedCommand) execution"
        author = "SIFT Sentinel"
        severity = "high"
        mitre = "T1059.001"

    strings:
        $e1 = " -EncodedCommand " nocase wide ascii
        $e2 = " -enc " nocase wide ascii
        $e3 = " -e " nocase wide ascii
        $bypass1 = "-ExecutionPolicy Bypass" nocase wide ascii
        $bypass2 = "-ep bypass" nocase wide ascii
        $hidden1 = "-WindowStyle Hidden" nocase wide ascii
        $hidden2 = "-w hidden" nocase wide ascii
        $noprofile = "-NoProfile" nocase wide ascii

    condition:
        (any of ($e*)) and (any of ($bypass*, $hidden*, $noprofile))
}

rule PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download cradle patterns (IEX, Invoke-Expression, DownloadString)"
        author = "SIFT Sentinel"
        severity = "high"
        mitre = "T1059.001, T1105"

    strings:
        $d1 = "IEX(" nocase ascii wide
        $d2 = "Invoke-Expression" nocase ascii wide
        $d3 = "DownloadString(" nocase ascii wide
        $d4 = "DownloadFile(" nocase ascii wide
        $d5 = "WebClient" nocase ascii wide
        $d6 = "Net.WebClient" nocase ascii wide
        $d7 = "Start-BitsTransfer" nocase ascii wide
        $d8 = "Invoke-WebRequest" nocase ascii wide
        $d9 = "curl " nocase ascii wide
        $d10 = "wget " nocase ascii wide

    condition:
        2 of them
}

// ---------------------------------------------------------------------------
// LOLBin Abuse
// ---------------------------------------------------------------------------

rule CertUtil_Decode_Abuse
{
    meta:
        description = "CertUtil used to decode or download files (LOLBin abuse)"
        author = "SIFT Sentinel"
        severity = "high"
        mitre = "T1140, T1105"

    strings:
        $s1 = "certutil" nocase wide ascii
        $s2 = "-decode" nocase wide ascii
        $s3 = "-urlcache" nocase wide ascii
        $s4 = "-split" nocase wide ascii
        $s5 = "-f http" nocase wide ascii

    condition:
        $s1 and (2 of ($s2, $s3, $s4, $s5))
}

rule MSHTA_Abuse
{
    meta:
        description = "mshta.exe executing remote script or VBScript"
        author = "SIFT Sentinel"
        severity = "high"
        mitre = "T1218.005"

    strings:
        $s1 = "mshta" nocase wide ascii
        $s2 = "vbscript:" nocase wide ascii
        $s3 = "javascript:" nocase wide ascii
        $s4 = "http://" nocase wide ascii
        $s5 = "https://" nocase wide ascii

    condition:
        $s1 and (any of ($s2, $s3) or ($s4 or $s5))
}

rule Regsvr32_Squiblydoo
{
    meta:
        description = "Regsvr32 Squiblydoo / remote SCT execution"
        author = "SIFT Sentinel"
        severity = "high"
        mitre = "T1218.010"

    strings:
        $s1 = "regsvr32" nocase wide ascii
        $s2 = "/s" nocase wide ascii
        $s3 = "/u" nocase wide ascii
        $s4 = "/n" nocase wide ascii
        $s5 = "/i:http" nocase wide ascii
        $s6 = "scrobj.dll" nocase wide ascii

    condition:
        $s1 and ($s5 or $s6)
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

rule Scheduled_Task_XML_Suspicious
{
    meta:
        description = "Scheduled task XML with suspicious execution path"
        author = "SIFT Sentinel"
        severity = "medium"
        mitre = "T1053.005"

    strings:
        $xml = "<?xml" ascii
        $task = "Task xmlns" ascii nocase
        $exec = "<Exec>" ascii
        $temp1 = "\\Temp\\" nocase wide ascii
        $temp2 = "\\AppData\\" nocase wide ascii
        $temp3 = "\\Users\\Public\\" nocase wide ascii
        $ps = "powershell" nocase wide ascii

    condition:
        $xml and $task and $exec and (any of ($temp*, $ps))
}

rule WMI_Permanent_Subscription
{
    meta:
        description = "WMI permanent event subscription strings (fileless persistence)"
        author = "SIFT Sentinel"
        severity = "high"
        mitre = "T1546.003"

    strings:
        $s1 = "__EventFilter" wide ascii
        $s2 = "__EventConsumer" wide ascii
        $s3 = "CommandLineEventConsumer" wide ascii
        $s4 = "ActiveScriptEventConsumer" wide ascii
        $s5 = "FilterToConsumerBinding" wide ascii

    condition:
        2 of them
}

// ---------------------------------------------------------------------------
// Network / C2 Patterns
// ---------------------------------------------------------------------------

rule Suspicious_IP_In_Binary
{
    meta:
        description = "Binary contains hardcoded RFC-1918 or suspicious IP:port combinations"
        author = "SIFT Sentinel"
        severity = "low"
        mitre = "T1071.001"

    strings:
        // Non-standard high ports with common C2 IPs
        $p1 = ":4444" ascii wide
        $p2 = ":8443" ascii wide
        $p3 = ":1337" ascii wide
        $p4 = ":31337" ascii wide
        $p5 = ":443" ascii wide
        // Known bad infrastructure patterns — update with case-specific IOCs
        $c2_pattern = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{4,5}/

    condition:
        uint16(0) == 0x5A4D and (2 of ($p*) or $c2_pattern)
}

// ---------------------------------------------------------------------------
// Anti-Analysis / Defense Evasion
// ---------------------------------------------------------------------------

rule Sandbox_Evasion_Checks
{
    meta:
        description = "Code checking for sandbox or analysis environment indicators"
        author = "SIFT Sentinel"
        severity = "medium"
        mitre = "T1497"

    strings:
        $v1 = "vmtoolsd.exe" nocase wide ascii
        $v2 = "VBoxService.exe" nocase wide ascii
        $v3 = "wireshark.exe" nocase wide ascii
        $v4 = "procmon.exe" nocase wide ascii
        $v5 = "procexp.exe" nocase wide ascii
        $v6 = "HKLM\\SOFTWARE\\VMware" nocase wide ascii
        $v7 = "VBOX" nocase wide ascii
        $v8 = "SandboxEnvironment" nocase wide ascii
        $v9 = "GetTickCount" ascii
        $v10 = "Sleep" ascii

    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Timestomping_Indicator
{
    meta:
        description = "Binary contains timestamps that predate typical Windows PE creation (potential timestomping)"
        author = "SIFT Sentinel"
        severity = "medium"
        mitre = "T1070.006"

    condition:
        uint16(0) == 0x5A4D and
        pe.timestamp < 978307200  // Before 2001-01-01 — almost certainly timestomped
}
