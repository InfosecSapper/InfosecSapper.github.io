---
title: explorer.exe
layout: post
permalink: /windows/explorer/
date: 2025-07-01
modified: 2026-07-29
group: Processes
---

## Overview

explorer.exe is the Windows Shell responsible for the graphical user interface, desktop, taskbar, file browsing, and much of the user's interactive experience.

In most interactive sessions, it becomes the user's long-lived parent process for applications launched through:

- The Start Menu
- File Explorer
- The Run dialog
- Desktop shortcuts
- File associations

### Expected Characteristics

#### Expected Location

- %SYSTEMROOT%\explorer.exe

#### Expected Parent

Typically:

    winlogon.exe
        └── userinit.exe
                └── explorer.exe

In some environments, visibility may show userinit.exe directly as the parent.

#### Typical Profile

- Long-running per user session
- Hosts the desktop shell
- Launches user applications
- Loads approved shell extensions
- Does not require unusual command-line parameters

## Why This Matters

explorer.exe persists for the entire interactive session and frequently launches applications, making it one of the busiest and most visible nodes in Windows process trees.

Attackers frequently abuse it for:

- Masquerading
- Code injection
- User-context execution
- Persistence through shell extensions
- Living-off-the-land activity that appears user-driven

Abnormal command lines, suspicious child processes, or unusual DLL loading can all indicate malicious activity.

### Relevant ATT&CK Techniques

- T1036 - Masquerading
- T1059 - Command and Scripting Interpreter
- T1204 - User Execution
- T1574.001 - DLL Search Order Hijacking
- T1055 - Process Injection

### Investigation Objective

Determine whether activity involving explorer.exe represents:

- Legitimate user behaviour
- Approved enterprise tooling
- User-initiated administration
- Adversary-driven execution
- Persistence through shell modification

## Normal Behaviour

### Characteristics

#### Path

- C:\Windows\explorer.exe

#### Parent

Typically:

    userinit.exe

via:

    winlogon.exe
        └── userinit.exe
                └── explorer.exe

#### Signature

- Microsoft Windows Publisher

#### Children

Common examples include:

- outlook.exe
- winword.exe
- excel.exe
- chrome.exe
- msedge.exe
- Approved enterprise applications

#### Lifetime

- Long-running
- Persists for the duration of the user session

### Typical Activity

- Loads trusted shell extensions
- Launches graphical applications
- Performs file operations
- Handles file associations
- Responds to user interaction

### Expected Behavioural Characteristics

explorer.exe:

- Commonly launches user applications
- Frequently appears as a parent process
- Handles file browsing operations
- Does not normally execute obfuscated commands
- Does not normally launch administrative tooling without user interaction

## Abuse Patterns

### Path or Signature Mismatch

Investigate immediately if:

- explorer.exe executes outside %SystemRoot%
- The binary is unsigned
- Metadata differs from the legitimate Microsoft binary

A non-standard explorer.exe should be treated as highly suspicious.

### Unexpected Parentage

Investigate explorer.exe launched by:

    powershell.exe

    cmd.exe

    wscript.exe

    cscript.exe

    mshta.exe

    rundll32.exe

or other LOLBins.

The standard parent should ultimately originate from userinit.exe.

### Abnormal Command Lines

Investigate:

- Encoded arguments
- Obfuscated command lines
- Excessively long command lines
- Script-engine redirection
- Base64 content
- Unusual command switches

explorer.exe rarely requires complex command-line arguments.

### Suspicious Child Processes

Examples include:

    powershell.exe

    cmd.exe

    wscript.exe

    cscript.exe

    mshta.exe

    rundll32.exe

Particularly when:

- The child originates from a user-writable location
- No obvious user interaction exists
- Network activity follows immediately

### User-Writable Execution Paths

Investigate binaries launched from:

- %TEMP%
- %APPDATA%
- %LOCALAPPDATA%
- Downloads
- Browser caches
- Office temporary locations

These frequently appear following phishing and user-execution scenarios.

### Shell Extension Abuse

Investigate:

- Recently-installed shell extensions
- Unknown publishers
- Context-menu handlers
- COM registration changes
- Explorer DLL side-loading

Shell extensions provide a common persistence mechanism because Explorer loads them automatically.

### DLL Search Order Hijacking

Investigate:

- DLL side-loading
- Missing DLL dependencies
- Alternate DLL search paths
- Newly introduced DLLs near trusted binaries

Because explorer.exe loads many extensions and handlers, it can become a target for DLL hijacking attacks.

### Explorer Restart Behaviour

Investigate:

- Unexpected Explorer crashes
- Repeated Explorer restarts
- Restarts immediately followed by DLL loading

Persistence mechanisms often reveal themselves during Explorer restarts.

## Detection Opportunities

### Parent-Child Relationship Analysis

Monitor for:

- Explorer launching script engines
- Explorer launching LOLBins
- Explorer launching binaries from user-writable locations
- Explorer spawning administrative tooling unexpectedly

Understanding the surrounding user activity is essential when interpreting these events.

### Command-Line Analytics

Investigate:

- Encoded commands
- Obfuscated parameters
- Long command lines
- URLs
- PowerShell launched through Explorer

These events often provide stronger signals than process names alone.

### User Context Correlation

Correlate:

- File opens
- Downloads
- USB activity
- Archive extraction
- Document execution

Many malicious Explorer-related events become obvious once user actions are reviewed alongside process telemetry.

### DLL and Shell Extension Monitoring

Monitor for:

- New shell extensions
- Rare DLLs
- Unsigned DLLs
- COM registration changes
- Explorer module load anomalies

Shell-extension persistence often leaves multiple artefacts available for detection.

### Process Injection Detection

Investigate:

- Memory modifications
- Thread injection alerts
- EDR tampering alerts
- Unusual module loads

Process injection into explorer.exe remains a popular method of running within a trusted process.

### Hunting Opportunities

Useful hunting pivots include:

- Explorer spawning PowerShell
- Explorer spawning LOLBins
- Rare child processes
- Shell-extension installations
- Explorer DLL loads from non-standard locations
- User-writable execution paths

The strongest findings usually emerge from combining user activity with process telemetry.

## False Positives

Legitimate Explorer activity can vary significantly between users and environments.

### Enterprise Shell Extensions

Examples include:

- Cloud storage providers
- DLP solutions
- Security products
- Endpoint management tooling

These frequently load DLLs into Explorer.

### Enterprise Management Software

Examples include:

- File classification platforms
- Endpoint management agents
- Virtualisation tooling
- Security enforcement products

Such software may hook Explorer to enforce policy.

### User-Initiated Scripting

Developers, administrators, and power users may legitimately launch:

- PowerShell
- Command Prompt
- Script engines

through Explorer.

Context is critical.

### Validation Questions

Check:

- Publisher
- Binary path
- User activity
- Parent process
- Shell extension prevalence
- Enterprise deployment status

Determine whether execution aligns with a reasonable user action.

### Estate-Wide Comparison

Legitimate enterprise tooling usually exhibits:

- High prevalence
- Consistent publishers
- Consistent paths
- Predictable behaviour

Rare behaviour deserves additional scrutiny.

## Hardening Recommendations

### Application Control

Consider:

- WDAC
- AppLocker
- Application allow-listing

Restrict execution of binaries from user-writable locations wherever possible.

### Reduce User-Writable Execution

Focus on:

- Downloads
- AppData
- Temp directories
- Browser cache locations

Reducing execution opportunities significantly limits user-context malware.

### Shell Extension Governance

Maintain an inventory of:

- Approved shell extensions
- Approved context-menu handlers
- Approved Explorer integrations

Unknown extensions should be investigated promptly.

### Monitor Explorer Persistence Mechanisms

Review:

- Shell extension registrations
- COM objects
- Registry-based Explorer customisations
- Startup entries interacting with Explorer

These provide common persistence opportunities.

### User Awareness and Execution Controls

Many Explorer-centred attacks rely on:

- User clicks
- Archive extraction
- Document execution

Reducing successful user execution reduces the effectiveness of many Explorer-based attack paths.

### Defensive Validation

Regularly test:

- Explorer child-process detections
- Shell-extension monitoring
- DLL hijacking detections
- User-execution analytics

Validation should be based on realistic user workflows rather than isolated demonstrations.

## Triage Checklist

### Identity and Integrity

- Verify image path is %SystemRoot%\explorer.exe
- Verify Microsoft Windows Publisher signature
- Review OriginalFileName metadata
- Confirm expected parentage

### Lineage and Behaviour

- Review child processes
- Review command-line arguments
- Identify LOLBins
- Investigate user-writable execution paths

### Shell Extension Review

- Enumerate loaded shell extensions
- Review COM registrations
- Identify unknown publishers
- Check for unusual DLL locations

### Context and Scope

- Correlate with user actions
- Review browser downloads
- Review archive extraction
- Review USB activity
- Review document execution

### Escalation Considerations

Escalate when:

- Persistence mechanisms are identified
- Script engines launch unexpectedly
- User-writable execution is observed
- Injection indicators are present

## ATT&CK References

- T1036 - Masquerading
- T1059 - Command and Scripting Interpreter
- T1204 - User Execution
- T1574.001 - DLL Search Order Hijacking
- T1055 - Process Injection

## Related Topics

### Windows Processes

- winlogon.exe
- userinit.exe
- explorer.exe
- rundll32.exe
- powershell.exe

### Windows Shell

- Shell Extensions
- File Associations
- COM Registration
- Context Menu Handlers

### MITRE ATT&CK

- T1036 - Masquerading
- T1059 - Command and Scripting Interpreter
- T1204 - User Execution
- T1574.001 - DLL Search Order Hijacking
- T1055 - Process Injection
