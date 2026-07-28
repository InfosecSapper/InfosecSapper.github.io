---
title: rundll32.exe
layout: post
permalink: /windows/rundll32/
---

## Overview

rundll32.exe is a built-in Windows utility used to load and execute functions exported from DLL files.

It exists to allow Windows components, many of which ship as DLLs, to run small pieces of functionality without needing full standalone executables. rundll32.exe acts as a simple wrapper for DLLs, as they're not directly executable.

    rundll32.exe <dll>,<exported_function> [arguments]

### Expected Characteristics

#### Expected Location

- %SYSTEMROOT%\System32\rundll32.exe
- %SYSTEMROOT%\SysWOW64\rundll32.exe on 64-bit systems

#### Expected Parent

- Varies widely depending on which Windows feature invoked it

#### Typical Profile

- Short-lived
- Used by Windows components, Control Panel items, and some legacy features

## Why This Matters

rundll32.exe appears frequently in triage because it is a flexible execution mechanism. Legitimate use does exist, but malicious use is more common, especially for execution, persistence, and lateral movement.

Common adversary use cases include:

- Loading malicious DLLs from user-writable paths
- Executing JavaScript or HTA content through COM components
- Launching scripts, payloads, or stagers via obscure DLL exports
- Masquerading or renaming rundll32.exe to bypass naïve detection
- Achieving stealthier execution than using cmd.exe or PowerShell directly

### Investigation Objective

Determine whether the DLL loaded by rundll32.exe is:

- A legitimate Windows component
- A trusted enterprise DLL
- Something unexpected

Particular attention should be paid to DLLs loaded from user-writable locations or newly-created paths.

## Normal Behaviour

### Characteristics

#### Path

- C:\Windows\System32\rundll32.exe
- C:\Windows\SysWOW64\rundll32.exe

#### Signature

- Microsoft Windows Publisher

#### Parents

- Control Panel items
- Windows settings applets
- Scheduled tasks for system maintenance
- OEM utilities
- Enterprise management tooling

#### Command Line

- References a DLL under %SystemRoot%
- Examples include shell32.dll, desk.cpl, and appwiz.cpl

#### Children

- Typically none
- rundll32.exe loads a DLL internally

### Typical Activity

- Launching Control Panel modules
- Displaying configuration windows
- Hosting legacy dialogs
- Supporting scheduled maintenance actions
- Loading Microsoft-signed DLLs from System32

## Abuse Patterns

### Path or Signature Mismatch

Investigate:

- rundll32.exe running from anywhere other than System32 or SysWOW64
- Unsigned copies
- Renamed executables

Examples:

    rundII32.exe

    run32dll.exe

### DLL Path Anomalies

Investigate DLLs loaded from:

- %TEMP%
- %APPDATA%
- %PROGRAMDATA%
- %PUBLIC%
- User profile paths

Additional concerns include:

- Recently dropped DLLs
- Recently modified DLLs
- Random names
- GUID-style names
- DLLs with no known application ownership

### Suspicious Export Functions

Investigate exports such as:

    Start

    EntryPoint

    Main

Windows components usually use predictable export names.

### Unexpected Parent Processes

Investigate rundll32.exe launched by:

- Browsers
- Office applications
- Script engines
  - wscript.exe
  - cscript.exe
- PowerShell
- Unzip utilities
- EDR-flagged binaries

### Suspicious Command Line Patterns

Look for:

- Obfuscated arguments
- Encoded arguments
- rundll32.exe used as a proxy for script execution

Common example:

    rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"

Also investigate:

- URL execution
- Remote payload retrieval
- Download-and-execute behaviour

### Child Process Anomalies

Investigate child processes such as:

    powershell.exe

    cmd.exe

    mshta.exe

    wscript.exe

Any unusual or unsigned child processes should be investigated.

## Detection Opportunities

### Process Ancestry

The parent process is often one of the strongest indicators available.

Investigate rundll32.exe when launched by:

- Microsoft Office applications
- Web browsers
- PowerShell
- cmd.exe
- wscript.exe
- cscript.exe
- Archive extraction utilities
- Previously flagged or unknown binaries

These relationships are far less common than Control Panel applets, system utilities, or enterprise management tooling launching rundll32.exe.

### DLL Path Analytics

The DLL being loaded is often more important than rundll32.exe itself.

Investigate DLLs loaded from:

- %TEMP%
- %APPDATA%
- %LOCALAPPDATA%
- %PUBLIC%
- User profile directories
- Network shares

Additional indicators include:

- Newly-created DLLs
- Recently-modified DLLs
- Low-prevalence DLLs
- Randomly-generated filenames
- DLLs lacking trusted publisher information

### Command-Line Analytics

Focus on the command line supplied to rundll32.exe.

Common indicators include:

- JavaScript execution
- COM object execution
- URLs
- Obfuscated arguments
- Encoded content
- Excessively long command lines

Example:

    rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"

Although some legitimate software uses unusual command lines, rare command lines generally warrant investigation.

### Child Process Indicators

rundll32.exe typically loads a DLL and exits without creating additional processes.

Investigate child processes such as:

    powershell.exe

    cmd.exe

    mshta.exe

    wscript.exe

    cscript.exe

Particular attention should be paid to scripting engines and LOLBins appearing immediately after rundll32.exe execution.

### Correlated Activity

A single rundll32.exe event rarely provides enough context on its own.

Review surrounding activity, including:

- File downloads
- Archive extraction
- Email attachment execution
- PowerShell activity
- Network connections
- Scheduled task creation
- Registry persistence mechanisms

The highest-confidence detections usually come from combining rundll32.exe activity with one or more additional suspicious events.

### Hunting Opportunities

Useful hunting approaches include:

- Rare rundll32.exe command lines
- Rare DLL paths
- User-writable DLL locations
- rundll32.exe executions followed by network activity
- rundll32.exe executions followed by PowerShell activity
- rundll32.exe executions occurring shortly after Office document opens

Focus on behaviours that are uncommon in your own environment rather than relying purely on static detection rules.

## False Positives

Although rundll32.exe is heavily abused, genuine cases exist, especially in environments with legacy applications or enterprise OEM utilities.

### Common Legitimate Scenarios

- Control Panel applets invoking rundll32.exe
- Enterprise application installers
- Driver utilities
- Scheduled tasks loading Microsoft DLLs
- Enterprise configuration tools

### Validation Questions

Check:

- DLL publisher
- DLL path
- DLL prevalence
- Whether the command line matches known Windows patterns
- Whether the parent process is expected
- Whether the behaviour occurs on known-good hosts
- Whether the DLL belongs to a known enterprise application

## Hardening Recommendations

### Application Control

Application allow-listing is one of the most effective mitigations for rundll32.exe abuse.

Consider:

- WDAC
- AppLocker
- Other enterprise application control technologies

The objective is not to block rundll32.exe itself, but to prevent unapproved DLLs from being executed.

### Restrict User-Writable Execution Paths

Adversaries frequently store payloads in locations where standard users can write files.

Review execution controls for:

- %TEMP%
- %APPDATA%
- %LOCALAPPDATA%
- %PUBLIC%
- Downloads folders

Reducing execution opportunities in these locations can significantly increase attacker workload.

### Attack Surface Reduction Rules

Where Microsoft Defender is available, Attack Surface Reduction (ASR) rules can help reduce common payload execution techniques.

Particularly relevant controls include:

- Blocking executable content from email and webmail clients
- Blocking Office child processes
- Blocking executable content from Office applications
- Restricting credential theft behaviours

ASR rules should be evaluated carefully to understand operational impact before broad deployment.

### Monitoring and Alerting

Monitoring should focus on behaviour rather than the mere presence of rundll32.exe.

Recommended telemetry includes:

- Process creation events
- Command-line logging
- DLL load events where available
- Parent-child process relationships
- Script execution activity
- Network connections

Alerting on every rundll32.exe execution will generate excessive noise.

Alerting on unusual rundll32.exe behaviour is significantly more effective.

### Administrative Hygiene

Review legitimate uses of rundll32.exe within the environment.

Questions to consider:

- Are legacy applications still dependent on rundll32.exe?
- Are there undocumented administration scripts?
- Are OEM utilities still required?
- Can unnecessary software be removed?

Reducing legitimate but unnecessary rundll32.exe usage improves signal-to-noise ratio and makes malicious activity easier to identify.

### Defensive Validation

Where possible, validate detections and controls using controlled testing.

Examples include:

- Loading a test DLL from a user-writable directory
- Evaluating command-line visibility in EDR tooling
- Testing detection logic against documented LOLBin techniques
- Measuring alert quality and false-positive rates

Controls should be assessed based on their ability to identify realistic abuse rather than simple proof-of-concept execution.

## Triage Checklist

### Identity and Integrity

- Verify rundll32.exe is running from System32 or SysWOW64
- Verify Microsoft signature
- Check OriginalFileName metadata
- Confirm the DLL is Microsoft-signed or a known enterprise component

### Lineage and Behaviour

- Inspect the parent process
- Examine the command line
- Look for unusual child processes

### DLL Context

- Determine DLL origin
- Review creation and modification timestamps
- Check prevalence across the estate
- Investigate suspicious exports
- Investigate recently dropped artefacts

### Scope

- Correlate activity with phishing activity
- Correlate activity with scripting activity
- Investigate potential user interaction
- Examine indicators of lateral movement

## ATT&CK References

- T1218.011 - Signed Binary Proxy Execution: Rundll32
- T1055 - Process Injection (DLL-based)
- T1036 - Masquerading

## Related Topics

### Windows Processes

- conhost.exe
- taskhost.exe
- regsvr32.exe
- svchost.exe
- lsass.exe

### MITRE ATT&CK

- T1218.011 - Signed Binary Proxy Execution: Rundll32
- T1055 - Process Injection
- T1036 - Masquerading
