---
title: powershell.exe
layout: post
permalink: /windows/powershell/
date: 2025-07-01
modified: 2026-07-29
group: Processes
---

## Overview

powershell.exe is the executable for Windows PowerShell, the automation and scripting environment built on the .NET Framework.

It provides:

- Command-line access
- Scripting capabilities
- Remote administration functionality
- Automation workflows
- Access to the .NET ecosystem
- Extensive administrative modules

PowerShell is used heavily by administrators, developers, management platforms, security tools, and attackers.

### Expected Characteristics

#### Expected Location

- %SYSTEMROOT%\System32\WindowsPowerShell\v1.0\powershell.exe

#### Expected Parent

Common examples include:

- explorer.exe
- Windows Terminal
- Visual Studio Code
- powershell_ise.exe
- Scheduled tasks
- Enterprise management tooling

#### Typical Profile

- Sporadic in standard user environments
- Common on servers
- Common on developer workstations
- Highly variable depending on operational requirements

## Why This Matters

PowerShell is one of the most flexible and capable execution environments available on Windows.

Its legitimate use is widespread.

Its abuse is equally widespread.

Attackers commonly use powershell.exe for:

- Initial execution
- Payload staging
- In-memory execution
- Discovery
- Reconnaissance
- Credential access
- Lateral movement
- Persistence
- Command and control

Modern attacks frequently avoid writing payloads to disk and instead rely entirely on PowerShell executing content directly in memory.

### Investigation Objective

Determine:

1. Whether the parent process is expected
2. Whether the command line is legitimate
3. Whether the observed behaviour aligns with normal administration or automation
4. Whether PowerShell is being used as part of a larger attack chain

The command line is often the single most important artefact during a PowerShell investigation.

## Normal Behaviour

### Characteristics

#### Path

- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

#### Signature

- Microsoft Windows Publisher

#### Parent Processes

Common examples include:

- explorer.exe
- powershell_ise.exe
- Visual Studio Code
- Scheduled tasks
- Enterprise automation platforms
- Server management tools

#### Command Line

Legitimate PowerShell usage usually contains:

- Readable commands
- Clear administrative intent
- Limited obfuscation
- Recognisable modules

#### Modules

Common legitimate examples include:

- ActiveDirectory
- Storage
- NetAdapter
- DnsServer
- Hyper-V

### Typical Activity

- System administration
- Patch management
- Enterprise automation
- Configuration management
- Inventory collection
- Security scanning
- Developer workflows

### Expected Behavioural Characteristics

PowerShell commonly:

- Executes scripts
- Accesses management APIs
- Interacts with WMI
- Performs automation tasks

In many desktop environments, PowerShell usage should be relatively infrequent.

On servers and administrator workstations it may be entirely normal.

## Abuse Patterns

### Suspicious Parent Processes

Investigate PowerShell launched by:

    mshta.exe

    rundll32.exe

    regsvr32.exe

    wscript.exe

    cscript.exe

    dllhost.exe

    winword.exe

    excel.exe

    outlook.exe

    browser processes

These relationships are frequently observed in phishing and malware execution chains.

### Remote Content Retrieval

Investigate command lines containing:

    DownloadString

    DownloadFile

    Invoke-WebRequest

    Invoke-RestMethod

    Net.WebClient

URLs within command lines frequently indicate staging or payload delivery.

### Encoded Commands

Investigate usage of:

    -EncodedCommand

    -enc

Particularly when combined with:

- Long Base64 strings
- Obfuscation
- Compressed data

Encoded commands are not automatically malicious, but they significantly increase investigative priority.

### Obfuscated Execution

Look for:

- Heavy escaping
- Character-by-character string construction
- Reflection APIs
- Dynamic code generation
- Nested execution

Examples include:

    IEX

    Invoke-Expression

and extensive manipulation of strings before execution.

### In-Memory Execution

Investigate PowerShell loading:

- Reflective DLLs
- Embedded payloads
- Downloaded scripts
- Encoded assemblies
- .NET binaries

Many modern payloads never touch disk.

### Hidden Execution

Investigate:

    -WindowStyle Hidden

    -NoProfile

    -ExecutionPolicy Bypass

particularly when appearing together.

These combinations frequently indicate attempts to reduce visibility.

### Persistence and Escalation Activity

Investigate commands modifying:

- Run keys
- Scheduled tasks
- WMI event subscriptions
- PowerShell profiles
- Service configurations

PowerShell is frequently used to establish persistence after initial compromise.

## Detection Opportunities

### Command-Line Analytics

The command line is often the highest-value source of telemetry.

Monitor for:

- Encoded content
- URLs
- DownloadString
- Invoke-WebRequest
- Invoke-Expression
- Reflection APIs

Rare PowerShell command lines should generally receive priority attention.

### Parent Process Analysis

Investigate PowerShell launched by:

- Office applications
- Browsers
- LOLBins
- PDF readers
- Archive utilities

Parent context often determines legitimacy.

### Script Block Logging

Where available, enable:

- PowerShell Script Block Logging
- PowerShell Module Logging
- PowerShell Operational Logs

These often provide visibility beyond the original command line.

### Child Process Monitoring

Investigate PowerShell spawning:

    cmd.exe

    rundll32.exe

    mshta.exe

    regsvr32.exe

    wscript.exe

    cscript.exe

and other LOLBins.

Chained LOLBin execution is a common attacker technique.

### Network Analytics

Monitor for:

- HTTP
- HTTPS
- DNS
- Unexpected outbound connections

PowerShell frequently serves as the bridge between execution and command-and-control activity.

### Hunting Opportunities

Useful hunting pivots include:

- Encoded commands
- Hidden windows
- NoProfile usage
- DownloadString usage
- Office-to-PowerShell chains
- Browser-to-PowerShell chains
- Rare modules

Focus on behaviour uncommon within your own environment.

## False Positives

PowerShell generates a significant number of legitimate alerts because many enterprise systems depend on it.

### Common Legitimate Scenarios

Examples include:

- SCCM
- Intune
- Endpoint management
- Security tooling
- Compliance automation
- Helpdesk tooling

### Cloud Administration

Examples include:

- Microsoft 365 administration
- Exchange administration
- Azure administration
- Entra administration

These workflows frequently use PowerShell.

### DevOps and Development

Examples include:

- Build pipelines
- Deployment tooling
- CI/CD platforms
- Developer environments

These systems often generate extensive PowerShell activity.

### Validation Questions

Check:

- Parent process
- Command-line intent
- Script path
- User context
- Change windows
- Administrative activity

Determine whether execution aligns with known operational workflows.

### Estate-Wide Context

Legitimate PowerShell activity often:

- Appears broadly across the estate
- Uses consistent command lines
- Aligns with scheduled jobs
- Matches documented automation

## Hardening Recommendations

### Constrained Language Mode

Where appropriate, evaluate:

- Constrained Language Mode
- Just Enough Administration
- Privileged Access Workstations

These controls can reduce PowerShell abuse opportunities.

### Script Signing

Require script signing where operationally feasible.

Benefits include:

- Improved change control
- Improved accountability
- Reduced unauthorised script execution

### Application Control

Consider:

- WDAC
- AppLocker
- Application allow-listing

Restrict execution of unapproved tools and scripts.

### Enable Comprehensive Logging

Implement:

- Script Block Logging
- Module Logging
- Process Creation Logging
- Command-Line Auditing

Visibility is often more valuable than prevention alone.

### Reduce Administrative Exposure

Limit:

- Standing privilege
- Excessive local administrator access
- Uncontrolled remote administration

Many PowerShell attack paths depend on elevated permissions.

### Defensive Validation

Test:

- Encoded-command detections
- Download-and-execute detections
- Office-to-PowerShell detections
- PowerShell persistence detections

Controls should be validated against realistic tradecraft rather than simple demonstrations.

## Triage Checklist

### Identity and Integrity

- Verify powershell.exe resides in the standard System32 location
- Confirm Microsoft signature
- Review OriginalFileName metadata
- Investigate non-standard paths

### Lineage and Behaviour

- Review the parent process
- Review the command line
- Review loaded modules
- Inspect any child processes

### Script and Content Analysis

- Determine script origin
- Review script contents
- Check file creation times
- Check prevalence across hosts

### Network and Operational Context

- Review outbound connections
- Review DNS activity
- Correlate with user behaviour
- Correlate with scheduled task activity

### Escalation Considerations

Escalate immediately if:

- Remote payload retrieval is confirmed
- Credential access activity is observed
- Lateral movement activity is identified
- Persistence mechanisms are established

## ATT&CK References

- T1059.001 - PowerShell
- T1105 - Ingress Tool Transfer
- T1027 - Obfuscated Files or Information
- T1547 - Boot or Logon Autostart Execution

## Related Topics

### Windows Processes

- wmiprvse.exe
- mshta.exe
- regsvr32.exe
- rundll32.exe
- wscript.exe

### PowerShell

- Script Block Logging
- Module Logging
- Execution Policy
- Constrained Language Mode
- Just Enough Administration

### MITRE ATT&CK

- T1059.001 - PowerShell
- T1105 - Ingress Tool Transfer
- T1027 - Obfuscated Files or Information
- T1547 - Boot or Logon Autostart Execution
