---
title: dllhost.exe
layout: post
permalink: /windows/dllhost/
date: 2025-07-01
modified: 2026-07-29
group: Processes
---

## Overview

dllhost.exe, known as the COM Surrogate, is a Windows host process responsible for loading and running COM objects on behalf of other applications.

Its purpose is to isolate potentially unstable or untrusted COM components so they do not crash or compromise the parent process.

In practice, dllhost.exe acts as a generic container process. It hosts whichever COM object it has been instructed to load.

### Expected Characteristics

#### Expected Location

- %SYSTEMROOT%\System32\dllhost.exe

#### Expected Parent

Varies depending on the calling application, but commonly includes:

- explorer.exe
- svchost.exe
- msiexec.exe
- Legitimate application processes

#### Typical Profile

- Often short-lived
- Appears when COM objects are required
- Commonly associated with thumbnails, previews, indexing, and application-specific components
- May appear frequently on workstations

## Why This Matters

COM objects are used throughout Windows and many third-party applications.

Examples include:

- Thumbnail generation
- Preview handlers
- Media codecs
- Browser extensions
- Office components
- Management tools
- Third-party application features

Because dllhost.exe executes COM components on behalf of other processes, attackers can abuse it to:

- Execute malicious COM objects
- Execute malicious DLLs
- Hide execution within a trusted Microsoft binary
- Establish persistence through COM hijacking
- Execute code from user-writable locations

### Investigation Objective

Determine whether the COM object being hosted is:

- Legitimate
- Enterprise-approved
- Expected for the parent process
- Malicious
- Part of a persistence mechanism

The process itself provides very little investigative value. The legitimacy of dllhost.exe depends entirely on the COM object it loads.

## Normal Behaviour

### Characteristics

#### Path

- C:\Windows\System32\dllhost.exe

#### Signature

- Microsoft Windows Publisher

#### Parent Processes

Common examples include:

- explorer.exe
- svchost.exe
- msiexec.exe
- Enterprise software
- Approved third-party applications

#### Children

- None

dllhost.exe should not normally spawn additional processes.

#### Lifetime

- Often short-lived
- Duration depends on the COM object being hosted

### Typical Activity

- Thumbnail rendering
- Explorer preview functionality
- Media codec handling
- File indexing
- COM automation
- Application plug-ins
- Document preview handlers

### Expected Behavioural Characteristics

dllhost.exe commonly appears during:

- File browsing
- Document previewing
- Office document handling
- Indexing operations
- Application startup

The presence of dllhost.exe alone is not inherently suspicious.

## Abuse Patterns

### Path or Signature Mismatch

Investigate immediately if:

- dllhost.exe executes outside System32
- The image is unsigned
- The filename has been modified
- Metadata differs from the Microsoft original

COM Surrogate is a common target for masquerading because many users are unfamiliar with the process.

### Suspicious Parent Processes

Investigate when dllhost.exe is launched by:

- Browsers
- Office applications
- Script engines
- LOLBins
- EDR-flagged binaries
- Unknown executables

Particularly when correlated with phishing activity or suspicious user actions.

### Unusual COM Object Loading

Investigate DLLs loaded from:

- %TEMP%
- %APPDATA%
- %LOCALAPPDATA%
- %PROGRAMDATA%
- Network shares

Additional concerns include:

- Newly-created DLLs
- Recently modified DLLs
- Unsigned DLLs
- Randomly-named DLLs
- Unknown COM registrations

### Unexpected Child Processes

dllhost.exe should not launch:

    powershell.exe

    cmd.exe

    mshta.exe

    wscript.exe

    cscript.exe

    rundll32.exe

Any child process should be considered highly suspicious.

### COM Hijacking

Investigate:

- Unexpected COM registrations
- Modified COM registrations
- CLSID registrations pointing to user-writable paths
- COM components loading unexpected DLLs

COM hijacking is frequently used to execute attacker-controlled code inside trusted Windows processes.

### Registry-Based Persistence

Particular attention should be paid to:

    HKCR\CLSID\{GUID}

Investigate:

- Recently modified registrations
- Unknown publishers
- User-writable DLL paths
- Unexpected InprocServer32 values

### Anomalous Frequency

Investigate:

- Repeated dllhost.exe launches
- Unusual launch frequency
- Activity without user interaction
- Activity on systems where COM usage would be unusual

Repeated execution often indicates unstable components, persistence mechanisms, or malicious automation.

## Detection Opportunities

### DLL Path Analytics

The hosted COM object is usually more important than dllhost.exe itself.

Investigate DLLs loaded from:

- Temp directories
- User profile paths
- Public directories
- Network locations
- Low-prevalence locations

### COM Registration Monitoring

Monitor changes to:

    HKCR\CLSID

and related COM registration paths.

Unexpected registration changes often indicate persistence attempts.

### Parent Process Analysis

Investigate parent-child relationships involving:

- Office applications
- Web browsers
- Script execution
- LOLBins

Parent context frequently reveals how the COM object was triggered.

### Child Process Monitoring

Alert on:

- PowerShell
- CMD
- Script hosts
- LOLBins
- Unsigned binaries

originating from dllhost.exe.

Legitimate COM Surrogate activity rarely results in process creation.

### DLL Load Monitoring

Investigate:

- Unsigned modules
- Rare modules
- Newly-created DLLs
- DLLs with low prevalence
- User-writable DLL locations

DLL load telemetry frequently provides the most useful evidence during COM investigations.

### Hunting Opportunities

Useful hunting pivots include:

- Rare COM registrations
- Rare CLSIDs
- User-writable COM paths
- Unusual parent processes
- Repeated dllhost.exe launches
- Non-standard DLL locations

The most valuable indicator is often the DLL being loaded rather than dllhost.exe itself.

## False Positives

dllhost.exe frequently generates alerts because many legitimate Windows features depend upon COM.

### Common Legitimate Scenarios

Examples include:

- Explorer thumbnail generation
- Office document previews
- PDF preview handlers
- Media codecs
- Search indexing
- Enterprise management software
- COM automation

### Enterprise Software

Many legitimate products utilise COM extensively, including:

- Document management platforms
- Security products
- Enterprise management tools
- Agent-based software

These may legitimately generate large volumes of dllhost.exe activity.

### Validation Questions

Check:

- DLL publisher
- DLL path
- Parent process
- Host prevalence
- CLSID registration
- Associated application

Determine whether the COM component appears consistently across known-good systems.

### User Activity Correlation

Review:

- File browsing
- Document viewing
- Search activity
- Application usage

Legitimate dllhost.exe activity is often directly tied to user actions.

## Hardening Recommendations

### Application Control

Consider:

- WDAC
- AppLocker
- Application allow-listing

Restrict execution of unauthorised DLLs where possible.

### COM Governance

Maintain visibility into:

- COM registrations
- CLSID changes
- InprocServer32 values
- New COM components

Unexpected changes should be investigated promptly.

### Restrict User-Writable DLL Execution

Reduce opportunities for DLL execution from:

- %TEMP%
- %APPDATA%
- %LOCALAPPDATA%
- %PUBLIC%

Many COM hijacking techniques depend on these locations.

### Monitor COM Persistence Mechanisms

Particular focus should be given to:

- CLSID registrations
- Shell extensions
- Explorer integrations
- Preview handlers

These commonly provide persistence opportunities.

### Maintain DLL Visibility

Ensure telemetry exists for:

- DLL loads
- Module loading
- COM registrations
- Persistence changes

Effective COM investigations often depend on DLL-level visibility.

### Defensive Validation

Regularly test:

- COM monitoring
- DLL load visibility
- COM hijacking detections
- Persistence monitoring

Controls should be validated against realistic COM abuse scenarios.

## Triage Checklist

### Identity and Integrity

- Verify dllhost.exe is located in System32
- Verify Microsoft signature
- Confirm filename accuracy
- Review OriginalFileName metadata

### Lineage and Behaviour

- Identify parent process
- Confirm there are no child processes
- Review launch frequency
- Correlate with user activity

### COM Context

- Identify the CLSID involved
- Review COM registrations
- Inspect DLL path
- Validate DLL signature
- Review creation timestamps

### Scope and Correlation

- Check prevalence across hosts
- Review phishing activity
- Review script execution
- Review persistence indicators
- Review lateral movement activity

### Escalation Considerations

Escalate when:

- COM hijacking is confirmed
- Unsigned DLLs are loaded
- Child processes are created
- User-writable DLL paths are involved

## ATT&CK References

- T1036 - Masquerading
- T1055 - Process Injection
- COM hijacking and related persistence techniques

## Related Topics

### Windows Processes

- regsvr32.exe
- rundll32.exe
- explorer.exe
- taskhost.exe
- powershell.exe

### COM and Persistence

- COM Registration
- CLSIDs
- COM Hijacking
- Shell Extensions
- Preview Handlers

### MITRE ATT&CK

- T1036 - Masquerading
- T1055 - Process Injection
