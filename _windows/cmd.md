---
title: cmd.exe
layout: post
permalink: /windows/cmd/
date: 2025-07-01
modified: 2026-07-29
group: Processes
---

## Overview

cmd.exe is the Windows Command Processor.

It provides a command-line interface for:

- Running built-in Windows commands
- Executing batch files (.bat)
- Executing command scripts (.cmd)
- Launching applications
- Automating administrative tasks
- Chaining execution between Windows utilities

It is one of the oldest and most widely-used Windows components and remains heavily utilised by administrators, installers, enterprise tooling, and attackers. 【1-6b6bcd】

### Expected Characteristics

#### Expected Locations

- %SYSTEMROOT%\System32\cmd.exe
- %SYSTEMROOT%\SysWOW64\cmd.exe

#### Expected Parents

Common examples include:

- explorer.exe
- powershell.exe
- msiexec.exe
- schtasks.exe
- Enterprise automation tools
- Administrative utilities

#### Typical Profile

- Common across most Windows environments
- Frequently used in administrative workflows
- Often appears in automation and deployment tooling
- More common on servers and administrator workstations than standard desktop endpoints

## Why This Matters

cmd.exe can appear at virtually any stage of an intrusion.

Attackers frequently use it because it provides a simple way to:

- Execute commands
- Launch payloads
- Chain LOLBins
- Run scripts
- Stage tools
- Perform reconnaissance
- Execute remote actions
- Establish persistence

Unlike some Windows binaries that have very narrow use cases, cmd.exe is so common that context becomes more important than process existence. 【1-6b6bcd】

### Common Investigation Scenarios

Analysts frequently encounter cmd.exe during:

- Phishing investigations
- Malware execution
- Persistence investigations
- Privilege escalation
- Lateral movement
- Software deployment
- Enterprise administration

### Investigation Objective

Determine:

- Who launched cmd.exe
- Why it was launched
- Which commands were executed
- Whether activity aligns with legitimate administration
- Whether cmd.exe is being used as part of a broader attack chain

The command line is usually the most valuable artefact during a cmd.exe investigation.

## Normal Behaviour

### Characteristics

#### Path

- C:\Windows\System32\cmd.exe
- C:\Windows\SysWOW64\cmd.exe

#### Signature

- Microsoft Windows Publisher

#### Parent Processes

Common examples include:

- explorer.exe
- powershell.exe
- msiexec.exe
- schtasks.exe
- Enterprise management platforms
- Administrative tooling

#### Children

May legitimately launch:

- Administrative utilities
- Batch scripts
- Deployment tooling
- Software-installation components

Child processes should align with a documented workflow.

#### Lifetime

- Usually short-lived
- Can remain active during administrative sessions
- Often exists only for the duration of a specific command

### Typical Activity

Legitimate examples include:

- Running scripts
- Software installation
- Maintenance tasks
- Troubleshooting
- Configuration management
- Automation workflows
- Developer activity

### Expected Behavioural Characteristics

Legitimate cmd.exe activity generally:

- Has a clear objective
- Uses readable command lines
- Aligns with known workflows
- Executes trusted binaries
- Operates from expected directories

## Abuse Patterns

### Suspicious Parent Processes

Investigate cmd.exe launched by:

- Browsers
- Office applications
- PDF readers
- Archive utilities
- mshta.exe
- rundll32.exe
- regsvr32.exe
- dllhost.exe
- Unknown executables

These parent-child relationships frequently appear during malware delivery and phishing campaigns. 【1-6b6bcd】

### LOLBin Chaining

Investigate cmd.exe launching:

    powershell.exe

    wscript.exe

    cscript.exe

    mshta.exe

    rundll32.exe

    regsvr32.exe

    schtasks.exe

    certutil.exe

    bitsadmin.exe

    curl.exe

While legitimate uses exist, extensive chaining often indicates malicious execution. 【1-6b6bcd】

### Obfuscated Command Lines

Investigate:

- Excessively long commands
- Base64-like strings
- Encoded content
- Heavy escaping
- Delayed variable expansion
- Complex piping
- Nested interpreters

Examples include:

    ^

    &

    |

    >

    >>

Complexity alone is not malicious, but unusual complexity should increase investigative priority. 【1-6b6bcd】

### User-Writable Execution Paths

Investigate scripts and binaries launched from:

- %TEMP%
- %APPDATA%
- %LOCALAPPDATA%
- %PROGRAMDATA%
- %PUBLIC%
- Downloads
- Desktop
- Network shares

Particularly when the files are newly created or low-prevalence.

### Batch-Based Staging

Attackers frequently use cmd.exe to:

- Download payloads
- Decompress archives
- Launch secondary stages
- Execute scripts
- Modify system configuration

The command processor often serves as a bridge between initial access and payload execution.

### Remote Execution Activity

Investigate cmd.exe used in conjunction with:

- PsExec
- WMI
- SMB administration
- Remote PowerShell
- Scheduled Tasks

Particularly when activity is observed across multiple systems.

### Persistence Activity

Review execution that modifies:

- Run keys
- RunOnce keys
- Scheduled tasks
- Services
- Startup folders

Many persistence mechanisms rely on cmd.exe wrappers.

## Detection Opportunities

### Command-Line Analytics

The command line is usually the most valuable source of telemetry.

Monitor for:

- Encoded content
- Download activity
- LOLBin execution
- Obfuscation
- URL references
- Hidden-window execution

Rare command lines often provide stronger signals than common administrative activity.

### Parent Process Monitoring

Investigate:

    winword.exe
        → cmd.exe

    excel.exe
        → cmd.exe

    browser.exe
        → cmd.exe

These chains frequently appear during initial access events.

### Child Process Monitoring

Investigate cmd.exe spawning:

- PowerShell
- Script hosts
- LOLBins
- Network utilities
- Unsigned binaries

The child process often reveals the attacker's objective.

### File and Script Monitoring

Review:

- Batch file execution
- Script locations
- Script prevalence
- Recently-created files

The file being executed frequently contains the strongest evidence.

### Network Analytics

Investigate when cmd.exe activity correlates with:

- DNS requests
- Web traffic
- File downloads
- External connectivity

Many command chains eventually interact with remote infrastructure.

### Hunting Opportunities

Useful hunting pivots include:

- Rare command lines
- Office-to-cmd execution
- Browser-to-cmd execution
- LOLBin chaining
- User-writeable execution paths
- New batch files

Prioritise unusual behaviour over sheer volume.

## False Positives

cmd.exe is heavily used throughout enterprise environments.

Context is critical.

### Common Legitimate Scenarios

Examples include:

- Software deployment
- Application installation
- Enterprise maintenance
- EDR remediation
- Configuration management
- Administrative scripting

### Developer Activity

Developers frequently generate:

- Long command lines
- Script execution
- Build automation
- Tool-chain activity

This frequently resembles attacker tradecraft at first glance.

### Enterprise Automation

Examples include:

- SCCM
- Intune
- Scheduled tasks
- Monitoring platforms
- Deployment tooling

Many enterprise systems rely on cmd.exe to orchestrate workflows.

### Validation Questions

Check:

- Parent process
- Command intent
- Script path
- User context
- Maintenance schedules
- Change windows

Determine whether the activity aligns with a legitimate operational process.

### Estate Context

Legitimate command lines often:

- Appear on many systems
- Align with administrative activity
- Execute known software
- Correspond with change-management records

## Hardening Recommendations

### Reduce Interpreter Chaining

Review workflows that unnecessarily chain:

- cmd.exe
- PowerShell
- Script hosts
- LOLBins

Simpler workflows are generally easier to monitor and secure.

### Application Control

Consider:

- WDAC
- AppLocker
- Application allow-listing

Prevent execution of unauthorised binaries and scripts.

### Restrict User-Writable Execution

Reduce opportunities for execution from:

- Downloads
- AppData
- Temp
- Public folders

Many attacker workflows rely on these locations.

### Improve Logging

Enable visibility into:

- Process creation
- Command-line arguments
- Script execution
- Network activity

High-quality telemetry is essential for cmd.exe investigations.

### Monitor Administrative Tooling

Review:

- Enterprise automation
- Scheduled tasks
- Deployment systems
- Privileged workflows

A clear baseline significantly reduces false positives.

### Defensive Validation

Regularly test:

- Command-line detections
- LOLBin analytics
- Parent-child process detections
- Application-control policies

Controls should be validated against realistic attacker workflows.

## Triage Checklist

### Identity and Integrity

- Verify cmd.exe resides in System32 or SysWOW64
- Verify Microsoft signature
- Review OriginalFileName metadata
- Check working directory

### Lineage and Behaviour

- Review parent process
- Review command line
- Identify child processes
- Review execution timeline

### File and Script Context

- Identify referenced scripts
- Review script paths
- Review script hashes
- Check prevalence across the estate

### Network and Execution Context

- Review DNS activity
- Review downloads
- Review external connections
- Correlate with user activity

### Scope and Correlation

- Compare against known-good baselines
- Correlate with PowerShell activity
- Correlate with LOLBin activity
- Correlate with persistence alerts

### Escalation Considerations

Escalate immediately when:

- Obfuscated commands are observed
- User-writeable execution paths are involved
- LOLBin chaining is identified
- Remote execution activity is confirmed
- Persistence mechanisms are modified

## ATT&CK References

- T1059.003 - Windows Command Shell
- T1204 - User Execution
- T1027 - Obfuscated Files or Information
- T1547 - Boot or Logon Autostart Execution

## Related Topics

### Windows Processes

- powershell.exe
- wscript.exe
- cscript.exe
- schtasks.exe
- mshta.exe

### Windows Scripting

- Batch Files
- Command Processors
- Windows Script Host
- PowerShell

### MITRE ATT&CK

- T1059.003 - Windows Command Shell
- T1204 - User Execution
- T1027 - Obfuscated Files or Information
- T1547 - Boot or Logon Autostart Execution
