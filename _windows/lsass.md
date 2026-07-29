---
title: lsass.exe
layout: post
permalink: /windows/lsass/
group: Processes
---

## Overview

LSASS (Local Security Authority Subsystem Service, lsass.exe) is the core Windows security process that enforces local security policy, validates credentials, maintains authentication packages, and manages Kerberos and NTLM operations.

Expected location:

- %SYSTEMROOT%\System32\lsass.exe

Expected parent:

- wininit.exe

Typical profile:

- Long-running
- High integrity
- Rarely spawns child processes

## Why This Matters

Attackers target lsass.exe to extract credentials and tokens from memory during or after initial access and prior to lateral movement.

Common behaviours align with MITRE ATT&CK:

- T1003.001 - OS Credential Dumping: LSASS Memory

Secondary techniques commonly encountered include:

- T1055 - Process Injection
- T1036 - Masquerading

### Investigation Objective

Determine quickly whether any observed interaction with lsass.exe is:

- A legitimate security product
- An expected Windows component
- A credential theft attempt

## Normal Behaviour

### Characteristics

#### Path

- C:\Windows\System32\lsass.exe

#### Parent

- wininit.exe

#### Signature

- Microsoft Windows Publisher

#### Command Line

- Consistent between boots

#### Lifetime

- Starts early during boot
- Remains present for the lifetime of the system

#### Children

- None in most environments

### Typical Activity

- Handles authentication flows and token generation
- Reads from SAM, SECURITY, and SYSTEM hives through LSA functions
- Loads Microsoft-signed authentication packages and Security Support Providers (SSPs)
- Interacts with components responsible for Kerberos and domain authentication

### Expected Behavioural Characteristics

- Rarely creates child processes
- Does not execute administrative tooling
- Does not directly create credential dump files
- Maintains predictable behaviour across reboots

## Abuse Patterns

### Path or Signature Mismatch

Investigate immediately if:

- lsass.exe is running outside System32
- The binary is unsigned
- Metadata does not match a legitimate Microsoft binary

Any lsass.exe instance outside System32 should be treated as malicious until proven otherwise.

### Unexpected Parent or Launch Mechanism

Investigate if:

- The parent process is not wininit.exe
- The process appears to have been hollowed
- The process appears to have been launched as a service
- The process lineage suggests masquerading

### High-Risk LSASS Memory Access

Investigate non-security products requesting:

- PROCESS_VM_READ
- PROCESS_QUERY_INFORMATION
- PROCESS_DUP_HANDLE

Particularly when access occurs immediately before:

- File creation
- Archive creation
- Network connections
- PowerShell activity

### Dump Artefacts and Tooling Patterns

Investigate:

- Newly created .dmp files
- Newly created .tmp files
- Dump files in Temp directories
- Dump files in ProgramData
- Dump files in user-writable locations

Common credential dumping patterns include:

#### comsvcs.dll MiniDump

    rundll32.exe comsvcs.dll, MiniDump

#### ProcDump

    procdump.exe -ma <pid>

    procdump.exe -64 <pid>

#### Other Tooling

- LiveKD
- Custom dumpers
- In-memory dump utilities

### Unexpected Child Processes

lsass.exe should not spawn child processes.

Any child process should be considered high severity.

Examples include:

    powershell.exe

    cmd.exe

    rundll32.exe

    wscript.exe

### Module and Injection Indicators

Investigate:

- Non-Microsoft DLLs loaded into LSASS
- Newly observed DLLs
- Unexpected SSPs
- Memory modification activity
- Evidence of code injection

### Defensive Exceptions

Security products may access LSASS.

However, legitimate access usually has the following characteristics:

- Signed binaries
- Consistent naming
- Consistent paths
- Estate-wide prevalence

One-off administrative tools should not automatically be considered trustworthy.

## Detection Opportunities

### Handle Access Monitoring

Monitor for processes opening handles to lsass.exe with:

- PROCESS_VM_READ
- PROCESS_QUERY_INFORMATION
- PROCESS_DUP_HANDLE

Particularly when the accessing process is:

- PowerShell
- rundll32.exe
- cmd.exe
- Unknown executables
- User-launched tools

### Process Creation Analytics

Investigate execution of tools commonly associated with credential dumping.

Examples include:

    procdump.exe

    rundll32.exe comsvcs.dll, MiniDump

Look for these processes shortly before:

- Dump file creation
- Network activity
- Lateral movement

### Dump File Monitoring

Search for:

- .dmp files
- .tmp files
- Large temporary files

Common locations include:

- %TEMP%
- %LOCALAPPDATA%
- %PROGRAMDATA%
- User profile directories

### Module Load Monitoring

Alert on:

- Newly observed SSPs
- Non-Microsoft DLLs
- Unusual authentication packages
- Rare modules loaded into LSASS

### Correlated Activity

High-confidence findings often involve multiple indicators.

Examples:

- LSASS handle access + dump file creation
- LSASS handle access + PowerShell execution
- LSASS handle access + network egress
- LSASS dump creation + lateral movement activity
- LSASS access + suspicious logon events

### Hunting Opportunities

Useful hunting pivots include:

- Rare processes accessing LSASS
- Rare SSP registrations
- Dump files across the estate
- Rundll32 MiniDump usage
- ProcDump execution
- Low-prevalence tooling interacting with LSASS

Focus on unusual behaviour rather than simple presence of an LSASS access event.

## False Positives

Legitimate security and platform components may access LSASS memory or enumerate tokens.

Validate publisher, path, and behavioural baselines carefully.

### Common Legitimate Scenarios

#### Security Products

Examples include:

- Microsoft Defender
- EDR agents
- Antivirus products

Characteristics:

- Microsoft-signed or vendor-signed
- Installed under Program Files
- Consistently observed across hosts

#### Enterprise EDR Platforms

Many EDR products:

- Open handles to LSASS
- Enumerate authentication materials
- Use protected drivers

Behaviour should be:

- Predictable
- Recurrent
- Consistent across the estate

#### Windows Error Reporting

Legitimate crash diagnostics may:

- Create dumps
- Interact with LSASS memory
- Use Microsoft tooling

### Administrative and Operational Activity

Examples include:

- Approved Process Explorer usage
- Performance monitoring tools
- Backup agents
- Maintenance tooling
- In-place upgrades
- Windows hotfixes

### Protected Process Light Considerations

Protected Process Light (PPL) can sometimes cause:

- Missing command lines
- Incomplete image paths
- Limited telemetry visibility

This can appear suspicious despite completely legitimate behaviour.

### Validation Questions

Check:

- Publisher
- Binary path
- Binary hash
- Expected deployment
- Observed prevalence
- Scheduled execution patterns
- Approved maintenance windows

Compare against a known-good host whenever possible.

## Hardening Recommendations

### Enable LSASS Protection

Where supported, enable:

- RunAsPPL
- Credential Guard

These controls significantly increase the difficulty of user-mode credential dumping.

### Reduce Administrative Exposure

Limit:

- Local administrator usage
- Shared administrator accounts
- Standing privileges

Reducing privileged credentials reduces the value of LSASS as a target.

### Application Control

Consider:

- WDAC
- AppLocker
- Application allow-listing

Preventing unauthorised tooling execution is often more effective than attempting to detect every credential dumper.

### Monitor Credential Access Techniques

Implement visibility for:

- LSASS memory access
- MiniDump execution
- ProcDump execution
- SSP registration changes
- Suspicious authentication package loading

### Restrict Interactive Administrative Activity

Prefer:

- Just-in-Time administration
- Privileged Access Workstations
- Controlled credential exposure

Reduce opportunities for privileged credentials to reside in memory on lower-trust systems.

### Validate Defensive Controls

Regularly test:

- Detection logic
- EDR visibility
- Credential dumping alerts
- Credential Guard effectiveness
- Response playbooks

Controls should be validated against realistic tradecraft rather than simple demonstrations.

## Triage Checklist

### Identity and Integrity Checks

- Verify image path is System32
- Verify Microsoft Windows Publisher signature
- Confirm parent is wininit.exe
- Inspect OriginalFileName metadata

### Access and Behaviour Checks

- Review handle opens to lsass.exe
- Investigate non-security products requesting read or duplicate handle rights
- Review recent module loads
- Check for unexpected SSPs
- Search for dump artefacts

### Service Context and Scope

- Correlate with PowerShell activity
- Correlate with WMI activity
- Correlate with token manipulation
- Correlate with unusual logon activity

### Containment Considerations

If indicators persist:

- Isolate the offending process
- Consider host isolation
- Preserve memory where policy permits
- Investigate credential exposure
- Review possible lateral movement

## ATT&CK References

- T1003.001 - OS Credential Dumping: LSASS Memory
- T1055 - Process Injection
- T1036 - Masquerading

## Related Topics

### Windows Processes

- winlogon.exe
- svchost.exe
- rundll32.exe
- services.exe
- wininit.exe

### Active Directory

- Kerberos
- NTLM
- Authentication Packages
- Security Support Providers

### MITRE ATT&CK

- T1003.001 - OS Credential Dumping: LSASS Memory
- T1055 - Process Injection
- T1036 - Masquerading
