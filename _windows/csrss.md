---
title: csrss.exe
layout: post
permalink: /windows/csrss/
date: 2025-07-01
modified: 2026-07-29
group: Processes
---

## Overview

csrss.exe (Client Server Runtime Subsystem) is a critical Windows subsystem process responsible for managing console windows, thread creation, process termination notifications, and certain Win32 subsystem operations.

Expected location:

- %SYSTEMROOT%\System32\csrss.exe

Expected parent:

- smss.exe

Typical profile:

- Multiple instances corresponding to system and user sessions
- Critical system process
- Does not spawn child processes

## Why This Matters

csrss.exe is essential to system stability. Interference often results in system crashes or forced reboots.

Attackers rarely interact with csrss.exe unless attempting masquerading, injection, or high-impact tampering.

Common ATT&CK techniques associated with observed anomalies include:

- T1036 - Masquerading
- T1055 - Process Injection

Any anomaly involving csrss.exe should be treated as a high-fidelity signal.

### Investigation Objective

Determine whether observed csrss.exe activity:

- Matches expected session behaviour
- Originates from the legitimate Windows binary
- Indicates process injection
- Indicates masquerading
- Indicates system-level tampering

Because csrss.exe is such a stable process, even minor anomalies can be significant.

## Normal Behaviour

### Characteristics

#### Path

- C:\Windows\System32\csrss.exe

#### Parent

- smss.exe

#### Signature

- Microsoft Windows Publisher

#### Instances

- One instance per session
- Includes Session 0

#### Children

- None

### Typical Activity

- Manages console windows
- Coordinates portions of the Win32 subsystem
- Supports process and thread management
- Handles session-related functions

### Expected Behavioural Characteristics

- Stable CPU utilisation
- Stable memory utilisation
- No direct network activity
- No script execution
- No command interpreter activity
- No dynamic module loading outside Microsoft binaries

In most environments, csrss.exe exhibits extremely consistent behaviour.

## Abuse Patterns

### Path or Signature Mismatch

Investigate immediately if:

- csrss.exe executes outside System32
- The binary is unsigned
- Metadata differs from the expected Microsoft binary

A csrss.exe instance outside System32 should be considered malicious.

### Unexpected Instance Counts

Investigate:

- Additional instances not explained by active sessions
- Missing expected instances
- Session counts not aligning with process counts

Unexpected csrss.exe population often indicates either visibility issues or serious system anomalies.

### Unexpected Child Processes

csrss.exe should never spawn child processes.

Investigate any child process, including:

    powershell.exe

    cmd.exe

    wscript.exe

    cscript.exe

    rundll32.exe

    mshta.exe

Any child process should be treated as a potential compromise indicator.

### Injection Indicators

Investigate:

- Non-Microsoft DLLs loaded into csrss.exe
- Thread injection events
- Memory modification alerts
- Process tampering events
- Unusual module loads

Because attackers rarely interact directly with csrss.exe, confirmed injection activity is particularly significant.

### Crash Correlation

Investigate whenever:

- Session failures occur
- Unexpected reboots occur
- Blue-screen events occur
- Kernel alerts occur

especially when correlated with csrss.exe anomalies.

### Defensive Exceptions

There are very few legitimate reasons for third-party software to interact directly with csrss.exe.

Unexpected activity should generally be treated as suspicious until proven otherwise.

## Detection Opportunities

### Process Lineage Monitoring

Validate:

- Parent process relationships
- Session ownership
- Instance creation patterns

The parent should always be smss.exe.

Unexpected lineage is a strong investigation trigger.

### Instance Count Monitoring

Track:

- Number of csrss.exe instances
- Session counts
- Session creation events

Unexpected increases or decreases may highlight compromised visibility or process tampering.

### Child Process Monitoring

Alert on:

- Any child process
- Any process execution chain beginning with csrss.exe

Legitimate environments should rarely, if ever, produce these events.

### Module and DLL Monitoring

Investigate:

- Non-Microsoft DLLs
- Newly-observed modules
- Rare module loads
- Suspicious memory mapping activity

Because csrss.exe typically loads only trusted Microsoft components, unusual modules can be high-confidence indicators.

### Injection Detection

Monitor for:

- Thread creation events
- Process injection alerts
- Memory modification events
- EDR process tampering detections

High-confidence detections generally come from behavioural indicators rather than simple process monitoring.

### Hunting Opportunities

Useful hunting pivots include:

- Non-System32 csrss.exe paths
- Child process creation
- Rare DLL loads
- Injection telemetry
- Session anomalies
- System instability correlated with process activity

Focus on anomalies. csrss.exe should demonstrate very little behavioural variation over time.

## False Positives

False positives are rare due to the limited and highly consistent behaviour of csrss.exe.

### Common Legitimate Scenarios

#### Telemetry Attribution Issues

Examples include:

- EDR sensor mapping issues
- Session attribution errors
- Process relationship misclassification

#### Partial Telemetry

Examples include:

- Sensor startup conditions
- Missing process events
- Incomplete session visibility

These may produce duplicate or inaccurate reporting.

### Validation Questions

Check:

- Session IDs
- Session counts
- Parent process
- Binary path
- Digital signature
- Alternate telemetry sources

Confirm that reported anomalies exist across multiple data sources before escalating.

## Hardening Recommendations

### Protect Critical System Processes

Ensure controls are in place to detect:

- Process injection
- Memory tampering
- Critical process modification
- Masquerading attempts

csrss.exe should be included in any monitoring of high-value Windows processes.

### Application Control

Consider:

- WDAC
- AppLocker
- Application allow-listing

Preventing execution of unauthorised software reduces opportunities for process tampering.

### Maintain High-Quality Telemetry

Monitor:

- Process creation
- Module loads
- Injection attempts
- Session creation
- Endpoint protection alerts

Reliable telemetry is essential because csrss.exe investigations are commonly driven by anomalies rather than volume.

### Monitor Critical Process Chain Integrity

Maintain visibility into:

- smss.exe
- csrss.exe
- wininit.exe
- winlogon.exe
- lsass.exe

Unexpected relationships between these processes should trigger investigation.

### Defensive Validation

Regularly validate:

- Process lineage detections
- Injection detections
- Endpoint visibility
- Session monitoring

Testing should focus on realistic tampering scenarios involving critical Windows processes.

## Triage Checklist

### Identity and Integrity Checks

- Verify image path is System32
- Confirm Microsoft Windows Publisher signature
- Confirm parent process is smss.exe
- Validate OriginalFileName metadata

### Behaviour Checks

- Confirm no child processes exist
- Review instance count
- Review session mapping
- Check for unusual modules

### Injection Checks

- Investigate memory modification events
- Investigate thread injection alerts
- Review loaded DLLs
- Identify non-Microsoft modules

### Context and Scope

- Correlate with system crashes
- Correlate with kernel alerts
- Correlate with session failures
- Escalate immediately if injection or masquerading is confirmed

## ATT&CK References

- T1036 - Masquerading
- T1055 - Process Injection

## Related Topics

### Windows Processes

- smss.exe
- wininit.exe
- winlogon.exe
- lsass.exe
- services.exe

### Session Management

- User Sessions
- Win32 Subsystem
- Session Initialisation
- Console Management

### MITRE ATT&CK

- T1036 - Masquerading
- T1055 - Process Injection
