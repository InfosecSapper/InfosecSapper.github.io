---
title: schtasks.exe
layout: post
permalink: /windows/schtasks/
group: Processes
---

## Overview

schtasks.exe is the command-line interface for Windows Task Scheduler.

It is used to:

- Create scheduled tasks
- Modify scheduled tasks
- Delete scheduled tasks
- Execute scheduled tasks
- Query scheduled tasks
- Manage task configuration

Scheduled tasks are used extensively by:

- Windows
- Enterprise management platforms
- Software installers
- Monitoring tools
- Administrators
- Attackers

### Expected Characteristics

#### Expected Location

- %SYSTEMROOT%\System32\schtasks.exe

#### Expected Parents

Common examples include:

- explorer.exe
- powershell.exe
- cmd.exe
- msiexec.exe
- SCCM
- Intune
- Enterprise deployment systems

#### Typical Profile

- Intermittent
- Administrative in nature
- Appears during installation and maintenance workflows
- Common in enterprise environments

## Why This Matters

Scheduled Tasks are one of the most popular persistence mechanisms available on Windows.

Attackers frequently abuse schtasks.exe to:

- Create persistence
- Schedule recurring execution
- Trigger malware at startup
- Trigger malware at logon
- Execute payloads as SYSTEM
- Establish privileged execution
- Stage lateral movement
- Execute one-time payloads

Unlike many persistence mechanisms, scheduled tasks generate artefacts across multiple operating system components, making them valuable investigative pivots.

### Investigation Objective

Determine:

- Who created the task
- When it was created
- What it executes
- Who it executes as
- How it is triggered
- Whether it represents legitimate automation or persistence

The task definition is usually more important than schtasks.exe itself.

## Normal Behaviour

### Characteristics

#### Path

- C:\Windows\System32\schtasks.exe

#### Signature

- Microsoft Windows Publisher

#### Parent Processes

Common examples include:

- explorer.exe
- cmd.exe
- powershell.exe
- msiexec.exe
- Enterprise automation tooling

#### Command Line

Typically:

- Clear and readable
- References known binaries
- References known scripts
- Aligns with administrative activity

### Typical Activity

Legitimate examples include:

- Software installation
- Software updates
- Enterprise maintenance
- Monitoring deployments
- Backup scheduling
- Compliance checks
- Operational automation

### Expected Behavioural Characteristics

Legitimate scheduled tasks generally:

- Execute from trusted locations
- Run known software
- Have meaningful names
- Appear consistently across the estate
- Align with maintenance windows

## Abuse Patterns

### Malicious Task Creation

Investigate tasks created to execute:

    powershell.exe

    cmd.exe

    wscript.exe

    cscript.exe

    mshta.exe

    rundll32.exe

    regsvr32.exe

particularly when combined with persistence triggers.

Attackers commonly use schtasks.exe to maintain execution after reboot or user logon.

### Suspicious Execution Paths

Investigate task actions referencing:

- %TEMP%
- %APPDATA%
- %LOCALAPPDATA%
- %PROGRAMDATA%
- Downloads
- User profile paths
- Network shares

Particular attention should be paid to newly-created files and low-prevalence binaries. 【1-6d81c5】

### Misleading Task Names

Attackers frequently create tasks with names such as:

- Windows Update
- System Maintenance
- Security Scan
- Driver Helper
- Backup Service
- Update Checker

Task names alone should never be trusted.

### Suspicious Trigger Types

Investigate:

- At startup
- At logon
- On unlock
- On idle
- On event
- Extremely frequent schedules

Examples include:

- Every minute
- Every five minutes
- Every user logon

These provide reliable persistence opportunities.

### SYSTEM-Level Execution

Investigate tasks:

- Created by standard users
- Running as SYSTEM
- Running with Highest Privileges enabled

This can indicate privilege escalation or unauthorised persistence.

### One-Shot Task Abuse

A common attacker pattern involves:

1. Create a task
2. Execute the task
3. Delete the task immediately afterwards

Examples:

    schtasks /create

    schtasks /run

    schtasks /delete

The task may exist for only a few seconds.

One-shot task abuse is frequently used for:

- Malware execution
- Lateral movement
- Operational security
- Red-team tradecraft

### Hidden or Rare Tasks

Investigate:

- Hidden tasks
- Tasks in unusual folders
- Tasks not present on comparable systems
- Recently-modified legacy tasks

Rarity is often a stronger signal than the task name itself.

### Suspicious Parent Processes

Investigate schtasks.exe launched by:

- Browsers
- Office applications
- PDF readers
- mshta.exe
- rundll32.exe
- cscript.exe
- wscript.exe
- Unknown executables

These relationships frequently indicate staged execution or phishing activity. 【1-6d81c5】

## Detection Opportunities

### Process Creation Monitoring

Monitor execution of:

    schtasks.exe

particularly command lines containing:

    /create

    /change

    /delete

    /run

These actions frequently precede malicious execution.

### Scheduled Task Logging

Review:

- Task creation events
- Task modification events
- Task deletion events
- Task execution events

Useful telemetry sources include:

- Windows Security Log
- Task Scheduler Operational Log
- Endpoint telemetry
- EDR process monitoring

### Task Definition Analysis

Review:

- Task name
- Task folder
- Trigger
- Action
- Principal
- Run level

The task definition often reveals attacker intent immediately.

### File-System Artefacts

Review:

    C:\Windows\System32\Tasks\

for:

- Recently-created tasks
- Unusual task names
- Hidden persistence mechanisms

Task XML files often contain complete execution details.

### Registry Artefacts

Review:

    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache

Useful locations include:

- Tree
- Tasks
- Plain
- Boot
- Logon

Changes here may reveal task creation, modification, or deletion activity.

### Parent-Child Process Analytics

Investigate relationships such as:

    Office
        → schtasks.exe

    Browser
        → schtasks.exe

    mshta.exe
        → schtasks.exe

These process chains are uncommon during normal business activity.

### Command-Line Analytics

Alert on:

- Encoded PowerShell
- Hidden PowerShell
- LOLBins
- Remote content retrieval
- Obfuscated commands

The scheduled task frequently acts only as a launcher for a second-stage payload.

### Hunting Opportunities

Useful hunting pivots include:

- Rare task names
- Hidden tasks
- New SYSTEM tasks
- Task creation immediately before security alerts
- Startup-triggered tasks
- Logon-triggered tasks
- User-writable execution paths

Task rarity often provides stronger hunting signals than task volume.

## False Positives

Scheduled tasks are extremely common throughout enterprise environments.

Context is critical.

### Common Legitimate Scenarios

Examples include:

- SCCM deployments
- Intune operations
- Monitoring platforms
- Backup software
- Software updates
- Hardware management tools
- Enterprise automation

### Installer Activity

Many installers create tasks for:

- Updates
- Scheduled maintenance
- Product telemetry
- Support tooling

Review associated installation activity before escalating.

### Validation Questions

Check:

- Task name
- Task path
- Publisher
- Binary location
- Trigger type
- Parent process

Determine whether the task supports a legitimate business process.

### Estate Context

Legitimate tasks often:

- Exist across large numbers of hosts
- Have consistent naming
- Align with maintenance schedules
- Execute trusted binaries

Prevalence is often an important validation signal.

## Hardening Recommendations

### Scheduled Task Governance

Maintain inventories of:

- Approved tasks
- Enterprise tasks
- Vendor-created tasks
- Administrative tasks

Unknown tasks should be investigated rapidly.

### Restrict Task Creation

Limit the ability to:

- Create tasks
- Modify tasks
- Execute privileged tasks
- Schedule SYSTEM-level execution

Reducing task management rights limits persistence opportunities.

### Application Control

Consider:

- WDAC
- AppLocker
- Application allow-listing

Preventing execution of unauthorised binaries reduces scheduled-task abuse opportunities.

### Restrict User-Writeable Execution Paths

Reduce execution opportunities from:

- AppData
- Temp
- Downloads
- Public folders

Many malicious tasks rely on user-controlled paths.

### Monitor Persistence Mechanisms

Scheduled tasks should be reviewed alongside:

- Services
- WMI subscriptions
- Run keys
- Startup folders

Attackers often establish multiple persistence mechanisms simultaneously.

### Review Privileged Tasks

Regularly audit:

- SYSTEM tasks
- Highest Privilege tasks
- Service-account tasks
- Hidden tasks

These carry greater risk than user-context tasks.

### Defensive Validation

Regularly test:

- Task creation detections
- Task deletion detections
- Persistence monitoring
- LOLBin execution chains

Controls should be validated against realistic attacker workflows.

## Triage Checklist

### Identity and Integrity

- Verify schtasks.exe resides in System32
- Verify Microsoft signature
- Confirm filename validity
- Review OriginalFileName metadata

### Lineage and Behaviour

- Review parent process
- Review command line
- Identify create, modify, run, or delete operations
- Review surrounding process activity

### Task Definition Review

Identify and review:

- Task name
- Task folder
- Trigger
- Action
- Arguments
- Run account
- Run level
- Creation time
- Modification time

### Storage Artefact Review

Review:

    C:\Windows\System32\Tasks\

and:

    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache

for supporting evidence.

### Scope and Correlation

- Compare against known-good baselines
- Review task prevalence
- Correlate with PowerShell activity
- Correlate with LOLBin execution
- Correlate with persistence alerts
- Correlate with authentication events

### Escalation Considerations

Escalate immediately when:

- SYSTEM-level persistence is identified
- User-writeable execution paths are involved
- Encoded PowerShell is scheduled
- One-shot task abuse is observed
- Hidden or deceptive tasks are discovered

## ATT&CK References

- T1053.005 - Scheduled Task
- T1547 - Boot or Logon Autostart Execution
- T1036 - Masquerading

## Related Topics

### Windows Processes

- powershell.exe
- cmd.exe
- taskhost.exe
- wscript.exe
- cscript.exe

### Persistence Mechanisms

- Scheduled Tasks
- Services
- WMI Event Subscriptions
- Run Keys
- Startup Folders

### MITRE ATT&CK

- T1053.005 - Scheduled Task
- T1547 - Boot or Logon Autostart Execution
- T1036 - Masquerading
