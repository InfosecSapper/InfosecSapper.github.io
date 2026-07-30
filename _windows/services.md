---
title: services.exe
layout: post
permalink: /windows/services/
date: 2025-07-01
modified: 2026-07-29
group: Processes
---

## Overview

services.exe is the Service Control Manager responsible for starting, stopping, and managing Windows services. It enforces service configuration, launches service host processes, and maintains service state.

Expected location:

- %SYSTEMROOT%\System32\services.exe

Expected parent:

- wininit.exe

Typical profile:

- Long running
- High privilege
- Centralised service management role

## Why This Matters

Attackers frequently abuse Windows services for persistence and privilege escalation by creating or modifying services that execute malicious payloads.

This behaviour aligns with MITRE ATT&CK:

- T1543.003 - Windows Service
- T1036 - Masquerading

services.exe activity is often the earliest indicator of service-based persistence.

### Investigation Objective

Determine whether services.exe is:

- Managing legitimate Windows services
- Managing legitimate third-party services
- Being abused for persistence
- Being abused for privilege escalation
- Managing unauthorised service creation or modification

Particular attention should be paid to newly-created services, suspicious image paths, and unusual service accounts.

## Normal Behaviour

### Characteristics

#### Path

- C:\Windows\System32\services.exe

#### Parent

- wininit.exe

#### Signature

- Microsoft Windows Publisher

#### Lifetime

- Starts during system initialisation
- Persists for the duration of system uptime

#### Children

Typically includes:

- svchost.exe
- Service-specific processes
- Legitimate service binaries

### Typical Activity

- Launches svchost.exe with valid service groups
- Starts service processes during system startup
- Starts services on demand
- Loads service binaries from legitimate installation locations
- Writes to service-related registry keys during software installation or updates

### Expected Behavioural Characteristics

- Stable long-running process
- Predictable service creation and startup activity
- Consistent interaction with Service Control Manager registry configuration
- Service launches aligned with configured startup behaviour

## Abuse Patterns

### Path or Signature Mismatch

Investigate immediately if:

- services.exe executes outside System32
- The binary is unsigned
- Metadata differs from the expected Microsoft binary

Any services.exe instance outside System32 should be treated as highly suspicious.

### Unexpected Child Processes

Investigate services.exe spawning:

    powershell.exe

    cmd.exe

    wscript.exe

    cscript.exe

    mshta.exe

    rundll32.exe

unless a legitimate and documented service explains the behaviour.

Particular attention should be paid to scripting engines and command interpreters.

### Service Creation or Modification Abuse

Investigate:

- Newly-created services
- Unexpected service modifications
- Auto-start services with unusual image paths
- Services configured to execute from user-writable directories

Examples include:

    %TEMP%

    %APPDATA%

    %PUBLIC%

    User profile paths

### Service Account Abuse

Investigate:

- Services running under unusual accounts
- Recently-created accounts assigned to services
- Services configured with excessive privileges

Attackers frequently use service configuration changes to establish persistence.

### One-Shot Service Behaviour

Investigate services that:

- Are created
- Started once
- Deleted immediately after execution

This pattern is frequently associated with lateral movement, remote execution, and malicious administration.

### Driver and Kernel Abuse

Investigate:

- Newly-installed kernel services
- Unrecognised drivers
- Unsigned drivers
- Vulnerable driver loading

Particular attention should be paid to Bring Your Own Vulnerable Driver (BYOVD) patterns.

## Detection Opportunities

### Event ID 7045 Monitoring

Windows Event ID 7045 remains one of the most valuable data sources for detecting service creation.

Investigate:

- New service installations
- Suspicious image paths
- Unusual service names
- Unexpected startup types

Where available, Event ID 7045 provides a strong starting point for triage.

### Service Registry Monitoring

Monitor:

    HKLM\SYSTEM\CurrentControlSet\Services

for:

- New keys
- Modified image paths
- Startup type changes
- Service account changes

Unexpected registry modifications frequently precede malicious service execution.

### Service Path Analytics

Investigate services executing from:

- User-writable locations
- Temporary directories
- Network shares
- Rare installation paths

The service binary often provides more investigative value than services.exe itself.

### Process Lineage Monitoring

Review:

- Parent-child relationships
- Service launch chains
- Child processes spawned by services.exe

Unexpected lineage often indicates misuse of legitimate service infrastructure.

### Driver Installation Monitoring

Alert on:

- New kernel drivers
- Unsigned drivers
- Rare drivers
- Vulnerable driver activity

Driver-based abuse can rapidly escalate to full system compromise.

### Hunting Opportunities

Useful hunting pivots include:

- Rare service names
- Rare service image paths
- New auto-start services
- One-shot services
- Services executing from user-writable locations
- Newly installed drivers

Prioritise service changes occurring immediately before suspicious activity elsewhere on the system.

## False Positives

Some legitimate scenarios may trigger alerts involving services.exe.

### Common Legitimate Scenarios

#### Software Installation and Updates

Examples include:

- Enterprise software deployment
- Software upgrades
- Application maintenance

These activities frequently create or modify services.

#### Endpoint Security Products

Examples include:

- EDR deployment
- AV installation
- Security platform upgrades

Many security products install or modify services as part of legitimate operation.

#### Driver Installation

Examples include:

- Hardware drivers
- Firmware management tools
- Operating system updates

Legitimate driver installation commonly generates service-related events.

### Validation Questions

Check:

- Publisher
- Digital signature
- Binary path
- Change management records
- Maintenance windows
- Deployment schedules
- Organisation-wide prevalence

Compare activity against known-good hosts where possible.

## Hardening Recommendations

### Service Governance

Maintain an inventory of:

- Approved services
- Third-party services
- Service owners
- Service dependencies

Unknown services should be investigated promptly.

### Restrict Service Creation

Limit the ability to:

- Create services
- Modify services
- Install software
- Register drivers

Reducing service creation opportunities substantially increases attacker workload.

### Application Control

Implement:

- WDAC
- AppLocker
- Application allow-listing

Preventing unauthorised service binaries from executing is often more effective than attempting to detect every persistence mechanism.

### Monitor Critical Service Infrastructure

Maintain visibility into:

- services.exe
- svchost.exe
- Service registry keys
- Service creation events
- Service account activity

Monitoring should focus on service behaviour rather than process existence.

### Service Account Management

Review:

- Privileged service accounts
- LocalSystem usage
- Newly-created service identities
- Unused service accounts

Service accounts should follow the principle of least privilege wherever possible.

### Defensive Validation

Test:

- Service creation detections
- Event ID 7045 visibility
- Registry monitoring
- Application control policies
- Service abuse response procedures

Defensive controls should be validated against realistic service-based persistence techniques.

## Triage Checklist

### Identity and Integrity Checks

- Verify image path is System32
- Verify Microsoft Windows Publisher signature
- Confirm parent is wininit.exe
- Inspect OriginalFileName metadata

### Service Behaviour Checks

- Review Event ID 7045 activity
- Review service registry keys
- Validate service image paths
- Review command-line arguments
- Confirm expected startup types
- Confirm expected service accounts

### Child Process Review

- Review child processes
- Investigate scripting engines
- Investigate command interpreters
- Investigate unexpected binaries
- Validate service ownership

### Context and Scope

- Determine whether activity is host-specific or fleet-wide
- Correlate with persistence alerts
- Correlate with privilege escalation activity
- Correlate with lateral movement activity

### Escalation Considerations

Escalate immediately if:

- Unauthorised services are identified
- Services execute from user-writable locations
- Driver abuse is observed
- Persistence mechanisms are confirmed

## ATT&CK References

- T1543.003 - Windows Service
- T1036 - Masquerading

## Related Topics

### Windows Processes

- svchost.exe
- smss.exe
- wininit.exe
- winlogon.exe
- lsass.exe

### Windows Services

- Service Control Manager
- Service Accounts
- Service Groups
- Service Registry Configuration

### MITRE ATT&CK

- T1543.003 - Windows Service
- T1036 - Masquerading
