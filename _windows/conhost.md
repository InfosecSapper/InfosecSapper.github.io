---
title: conhost.exe
layout: post
permalink: /windows/conhost/
date: 2025-07-01
modified: 2026-07-29
group: Processes
---

## Overview

conhost.exe (Console Window Host) is a Windows process responsible for hosting console applications and providing the interface between command-line programs and the Windows graphical environment.

Historically, console functionality was handled directly by csrss.exe. Modern Windows versions use conhost.exe to isolate console activity and improve both stability and security.

### Expected Characteristics

#### Expected Location

- %SYSTEMROOT%\System32\conhost.exe

#### Expected Parent

Common examples include:

- cmd.exe
- powershell.exe
- wsl.exe
- ssh.exe
- Scheduled task processes
- Service-hosted command-line utilities

#### Typical Profile

- Frequently observed
- Often multiple concurrent instances
- Associated with console applications
- Exists only while a console workload is active

## Why This Matters

conhost.exe itself is not typically the target of abuse.

However, attackers frequently use command-line tooling which naturally results in conhost.exe activity.

Because conhost.exe is associated with:

- PowerShell
- Command Prompt
- Remote administration tools
- Scripts
- Console-based malware

it often appears in process chains during investigations.

Anomalies involving conhost.exe can indicate:

- Masquerading
- Script execution
- Living-off-the-land activity
- Persistence
- Post-exploitation activity

### Relevant ATT&CK Techniques

- T1036 - Masquerading
- T1059 - Command and Scripting Interpreter
- T1055 - Process Injection

### Investigation Objective

Determine:

- Which process launched conhost.exe
- Whether the associated console activity is expected
- Whether the parent process is legitimate
- Whether conhost.exe is part of a larger attack chain

In most cases, the parent process is more important than conhost.exe itself.

## Normal Behaviour

### Characteristics

#### Path

- C:\Windows\System32\conhost.exe

#### Signature

- Microsoft Windows Publisher

#### Parent Processes

Common examples include:

    cmd.exe

    powershell.exe

    wsl.exe

    ssh.exe

    python.exe

    legitimate administrative tools

#### Children

- Usually none
- Where present, should align with the associated console workload

#### Lifetime

- Exists while the console session is active
- Terminates when the associated process exits

### Typical Activity

- Hosting Command Prompt sessions
- Hosting PowerShell sessions
- Supporting administrative tooling
- Providing console interfaces for scripts and automation
- Supporting scheduled tasks and maintenance operations

### Expected Behavioural Characteristics

conhost.exe:

- Is frequently observed
- Commonly appears alongside PowerShell and Command Prompt
- Does not normally perform network activity itself
- Does not normally load unusual modules
- Does not typically execute from user-writable locations

## Abuse Patterns

### Path or Signature Mismatch

Investigate immediately if:

- conhost.exe executes outside System32
- The image is unsigned
- The filename is altered

Examples include:

    conhst.exe

    conhost32.exe

    conh0st.exe

Masquerading involving conhost.exe is common because the process is familiar to many administrators.

### Suspicious Parent Processes

Investigate conhost.exe launched by:

- Office applications
- Web browsers
- Email clients
- LOLBins
- Script hosts
- Unknown executables

These relationships frequently indicate phishing-driven execution chains.

### Command-Line Abuse

Investigate conhost.exe associated with:

    powershell.exe

    cmd.exe

    wscript.exe

    cscript.exe

    mshta.exe

particularly when:

- Encoded commands are present
- Obfuscation is observed
- User-writable paths are involved

### Unexpected Child Processes

Although uncommon, investigate:

- PowerShell
- Command Prompt
- LOLBins
- Unsigned binaries

spawned directly from conhost.exe.

The parent console process is typically the primary execution context.

### Injection Indicators

Investigate:

- Memory modification events
- Thread injection alerts
- Unusual modules
- EDR tampering detections

Attackers occasionally inject into console-related processes to evade detection.

### Abnormal Volume

Investigate:

- Large numbers of conhost.exe instances
- Persistent conhost.exe execution
- Orphaned console sessions

These may indicate automation, malware activity, or process-management problems.

## Detection Opportunities

### Parent Process Analytics

The strongest detection opportunities usually come from the parent process.

Investigate conhost.exe when associated with:

- PowerShell
- Command Prompt
- Script engines
- Office applications
- Browsers

Particularly where execution patterns are uncommon for the environment.

### Command-Line Visibility

Monitor:

- Encoded PowerShell
- Obfuscated commands
- Download-and-execute patterns
- Base64 strings
- LOLBin abuse

These frequently surface through console-hosted processes.

### Process Chain Analysis

Review:

    Office
        → PowerShell
            → conhost.exe

or

    Browser
        → cmd.exe
            → conhost.exe

These chains often provide stronger signals than conhost.exe alone.

### Session Correlation

Correlate conhost.exe activity with:

- User logons
- Scheduled tasks
- Remote administration
- Phishing events
- Security alerts

The surrounding context usually determines legitimacy.

### Hunting Opportunities

Useful hunting pivots include:

- Rare parent processes
- Encoded PowerShell
- Long-running console sessions
- Large conhost.exe populations
- Unusual process chains
- User-writable execution paths

Focus on the workload being hosted rather than the console host itself.

## False Positives

conhost.exe is present on most Windows systems and frequently appears during legitimate administration.

### Common Legitimate Scenarios

Examples include:

- PowerShell administration
- Command Prompt usage
- Software installation
- Scheduled tasks
- Enterprise automation
- Developer tooling

### Administrative Activity

Developers and administrators commonly generate conhost.exe activity through:

- Terminal sessions
- Scripting
- Build systems
- Remote management

Context is critical.

### Enterprise Tooling

Examples include:

- Endpoint management platforms
- Monitoring tools
- Deployment frameworks
- Automation platforms

These may legitimately create large numbers of console-hosted processes.

### Validation Questions

Check:

- Parent process
- Associated command line
- User context
- Host prevalence
- Execution path
- Administrative intent

Determine whether the observed workload is expected rather than focusing solely on conhost.exe.

## Hardening Recommendations

### Reduce Script Abuse Opportunities

Review controls relating to:

- PowerShell
- Command Prompt
- Windows Script Host
- LOLBins

Many suspicious conhost.exe events originate from abuse of these technologies.

### Application Control

Consider:

- WDAC
- AppLocker
- Application allow-listing

Prevent unauthorised command-line tooling from executing.

### PowerShell Visibility

Enable:

- Script Block Logging
- PowerShell Operational Logging
- Enhanced process creation auditing

Visibility into PowerShell activity often provides far more value than monitoring conhost.exe alone.

### Process-Creation Monitoring

Maintain telemetry for:

- Parent-child relationships
- Command lines
- Module loads
- Process creation events

This provides valuable context during investigations.

### Administrative Governance

Review:

- Scheduled tasks
- Automation tooling
- Remote administration practices
- Local administrative usage

Reducing unnecessary console activity improves signal-to-noise ratios.

### Defensive Validation

Regularly test:

- PowerShell detections
- Command-line visibility
- LOLBin detections
- Process chain analytics

Detection quality should be measured against realistic attack patterns.

## Triage Checklist

### Identity and Integrity

- Verify image path is System32
- Verify Microsoft signature
- Confirm filename validity
- Review OriginalFileName metadata

### Parent Process Review

- Identify the parent process
- Review the command line
- Determine execution purpose
- Investigate unusual ancestry

### Behaviour Review

- Review associated console activity
- Identify child processes
- Review process duration
- Check for suspicious modules

### Scope and Context

- Correlate with user activity
- Correlate with PowerShell execution
- Correlate with phishing indicators
- Review related alerts

### Escalation Considerations

Escalate when:

- Masquerading is observed
- Encoded commands are present
- Suspicious parent-child relationships exist
- Process injection indicators are identified

## ATT&CK References

- T1036 - Masquerading
- T1059 - Command and Scripting Interpreter
- T1055 - Process Injection

## Related Topics

### Windows Processes

- powershell.exe
- cmd.exe
- csrss.exe
- explorer.exe
- taskhost.exe

### Command-Line Activity

- PowerShell
- Command Prompt
- Windows Terminal
- Windows Script Host

### MITRE ATT&CK

- T1036 - Masquerading
- T1059 - Command and Scripting Interpreter
- T1055 - Process Injection
