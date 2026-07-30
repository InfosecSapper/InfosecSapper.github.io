---
title: spoolsv.exe
layout: post
permalink: /windows/spoolsv/
date: 2025-07-01
modified: 2026-07-29
group: Processes
---

## Overview

spoolsv.exe is the Windows Print Spooler service.

It is responsible for:

- Managing print queues
- Processing print jobs
- Loading printer drivers
- Communicating with printers
- Communicating with print servers
- Managing printer configuration

The service runs under the LocalSystem account and is typically present on most Windows systems, regardless of whether they are actively used for printing.

### Expected Characteristics

#### Expected Location

- %SYSTEMROOT%\System32\spoolsv.exe

#### Expected Parent

- services.exe

#### Typical Profile

- Long-running service
- Starts during boot
- Persists until shutdown
- Usually exhibits stable resource consumption
- Primarily active when printers, print queues, or drivers are involved

## Why This Matters

Although spoolsv.exe is not commonly associated with day-to-day attacker activity, it remains one of the most security-sensitive Windows services.

It regularly appears during investigations for three reasons:

### Print Spooler Vulnerabilities

The Windows Print Spooler has a long history of security vulnerabilities.

Notable classes of weakness have included:

- Remote Code Execution (RCE)
- Privilege Escalation
- Driver-loading abuse
- Authentication relay attacks

The most widely publicised examples were the various PrintNightmare vulnerability chains, which demonstrated how a trusted Windows service could be abused to execute attacker-controlled code.

### Unexpected Process Creation

spoolsv.exe should not function as a general-purpose process launcher.

Any child process originating from spoolsv.exe deserves investigation.

Examples include:

    powershell.exe

    cmd.exe

    wscript.exe

    cscript.exe

    mshta.exe

    rundll32.exe

    regsvr32.exe

    certutil.exe

These relationships are rarely legitimate.

### Driver Loading Activity

The Print Spooler routinely loads printer drivers and supporting DLLs.

Because printer drivers execute in a privileged context, this area has repeatedly become a target for:

- Privilege escalation
- Code execution
- DLL abuse
- Persistence

Investigators should pay close attention to new printer-driver deployments and unusual module loading behaviour.

### Investigation Objective

Determine whether spoolsv.exe is:

- Performing legitimate printing operations
- Loading trusted printer drivers
- Exhibiting signs of exploitation
- Being abused for privilege escalation
- Being leveraged for persistence or execution

## Normal Behaviour

### Characteristics

#### Path

- C:\Windows\System32\spoolsv.exe

#### Parent

- services.exe

#### Signature

- Microsoft Windows Publisher

#### Lifetime

- Long-running
- Starts automatically during boot
- Remains active until shutdown

#### Children

Normally:

- None

spoolsv.exe should not routinely launch scripting engines, consoles, administrative tools, or LOLBins.

### Typical Activity

Legitimate activity includes:

- Installing printer drivers
- Updating printer drivers
- Processing print jobs
- Managing print queues
- Enumerating printers
- Communicating with print servers

### Expected Behavioural Characteristics

A normal spoolsv.exe instance generally demonstrates:

- Stable CPU usage
- Stable memory usage
- Minimal process creation activity
- Predictable printer-related module loading

### Network Behaviour

Some network activity is expected when:

- Communicating with print servers
- Discovering network printers
- Submitting print jobs

Connections should generally align with known printing infrastructure.

## Abuse Patterns

### Unexpected Child Processes

Any child process should be considered unusual.

Investigate immediately if spoolsv.exe launches:

    powershell.exe

    cmd.exe

    wscript.exe

    cscript.exe

    mshta.exe

    rundll32.exe

    regsvr32.exe

    certutil.exe

    curl.exe

    unsigned executables

Attackers frequently leverage privileged services to launch follow-on payloads.

### Path or Signature Mismatch

Investigate immediately if:

- spoolsv.exe executes outside System32
- The binary is unsigned
- The digital signature is invalid
- PE metadata differs from expected Microsoft values

Examples include:

    spoolsvc.exe

    spoolvs.exe

    spoolsvv.exe

### Printer Driver Abuse

Investigate:

- Newly-installed printer drivers
- Unexpected driver updates
- Drivers installed outside maintenance windows
- Third-party drivers from unfamiliar vendors

Printer drivers execute with significant privileges and represent a common attack surface.

### Unsigned or Rare Driver Loading

Particular attention should be paid to:

- Unsigned drivers
- Rare drivers
- Drivers loaded from unusual locations
- Drivers with low prevalence across the estate

Drivers loaded from user-writeable locations should be treated as highly suspicious.

### PrintNightmare-Style Activity

Review:

- New printer objects
- Driver installation events
- Spooler configuration changes
- Remote printer administration activity

Unexpected administrative activity involving the Print Spooler may indicate exploitation attempts.

### DLL Loading Anomalies

Investigate:

- Non-Microsoft modules
- Printer-related DLLs
- Newly-created DLLs
- Rare modules
- Modules from non-standard paths

Attackers may abuse spoolsv.exe by introducing malicious components into normal driver workflows.

### Service Manipulation

Investigate:

- Registry modifications
- Service account changes
- Service permissions changes
- Start-type modifications

Malicious changes to Print Spooler configuration frequently accompany persistence or privilege-escalation activity.

### Resource Consumption Anomalies

Investigate:

- CPU spikes
- Memory spikes
- Excessive handle counts
- Repeated crashes
- Service restarts

Potential causes include:

- Exploit attempts
- Malicious drivers
- Faulty drivers
- Malformed print jobs

## Detection Opportunities

### Child Process Analytics

One of the highest-fidelity detections involving spoolsv.exe is:

    spoolsv.exe
        └── any child process

Legitimate process creation is extremely uncommon.

### Printer Driver Installation Monitoring

Monitor:

- New driver installation
- Driver updates
- Driver removal
- Driver loading failures

Changes involving printer drivers often precede abuse.

### DLL and Module Monitoring

Review:

- Loaded modules
- Driver DLLs
- Rare DLLs
- Unsigned DLLs
- DLLs loaded from unusual directories

Module-load telemetry frequently provides earlier indicators than process telemetry.

### PrintService Operational Logs

Review:

- Driver installation events
- Printer installation events
- Print-service failures
- Service-operation logs

These logs frequently provide context that is missing from process telemetry alone.

### Registry Monitoring

Review changes involving:

- Printer configuration
- Driver configuration
- Service configuration

Unexpected changes should be investigated.

### Network Analytics

Investigate:

- Connections to unfamiliar hosts
- Connections outside known print infrastructure
- Unusual remote administration activity

The Print Spooler should not exhibit arbitrary outbound communication.

### Hunting Opportunities

Useful hunting pivots include:

- Rare printer drivers
- Unsigned printer drivers
- New print-server relationships
- Child-process creation
- Driver installation outside maintenance windows
- Systems exhibiting print activity despite having no business requirement to print

## False Positives

spoolsv.exe is fundamentally a legitimate system service.

Not all unusual activity is malicious.

### Common Legitimate Scenarios

Examples include:

- Printer installation
- Driver upgrades
- Printer troubleshooting
- Queue resets
- Enterprise print deployments

### Enterprise Print Infrastructure

Large organisations often generate:

- Frequent printer-driver updates
- Printer discovery traffic
- Queue-management activity
- Print-server communications

These activities may generate alerts without indicating compromise.

### Virtual Printer Products

Examples include:

- PDF printers
- Document management systems
- Label-printing solutions
- Virtual print infrastructure

Many of these products rely heavily on Print Spooler functionality.

### Validation Questions

Check:

- Was a printer recently installed?
- Was a driver recently updated?
- Is the driver signed?
- Is the activity consistent across similar systems?
- Was printing occurring at the time?

## Hardening Recommendations

### Disable Print Spooler Where Unnecessary

Many systems have no operational requirement for printing.

Strong candidates include:

- Domain Controllers
- Infrastructure servers
- Management servers
- Security appliances

Removing unnecessary services reduces attack surface substantially.

### Restrict Printer Driver Installation

Review:

- Who can install drivers
- How drivers are deployed
- Which vendors are approved

Driver installation should be tightly controlled.

### Review Point-and-Print Configuration

Ensure:

- Trusted print servers are defined
- Driver installation restrictions are enforced
- Point-and-Print policies are reviewed regularly

Historically, Point-and-Print has featured heavily in exploitation chains.

### Application Control

Consider:

- WDAC
- AppLocker
- Application allow-listing

These controls reduce opportunities for malicious components to execute through printer infrastructure.

### Monitor Printer Administration Activity

Review:

- Driver installation
- Printer creation
- Printer deletion
- Print-server management

Administrative actions should be attributable and auditable.

### Audit Privileged Access

Limit:

- Printer administration rights
- Driver installation rights
- Service-management rights

Excessive privileges increase the impact of exploitation.

### Defensive Validation

Regularly test:

- Child-process detection logic
- Driver monitoring controls
- Print-service logging
- Service-hardening controls

## Triage Checklist

### Identity and Integrity

- Verify spoolsv.exe resides in System32
- Verify Microsoft signature
- Confirm parent is services.exe
- Review OriginalFileName metadata

### Behaviour and Lineage

- Investigate any child processes
- Review command lines
- Review resource consumption
- Review service state changes

### Driver Review

- Identify newly-installed drivers
- Review driver signatures
- Validate driver paths
- Identify low-prevalence drivers

### Module Review

- Examine loaded DLLs
- Identify unsigned modules
- Identify non-standard load paths
- Investigate rare components

### Print Context

- Review print queues
- Review printer installation activity
- Review driver deployment activity
- Review print-server interactions

### Scope and Correlation

- Compare behaviour across hosts
- Review recent administrative activity
- Correlate with privilege-escalation alerts
- Correlate with service-modification events
- Correlate with security monitoring alerts

### Escalation Considerations

Escalate immediately if:

- Child processes exist
- Unsigned drivers are loaded
- Driver paths are suspicious
- Service manipulation is identified
- Print Spooler exploitation is suspected

## ATT&CK References

- T1036 - Masquerading
- T1574 - Hijack Execution Flow
- T1068 - Exploitation for Privilege Escalation

## Related Topics

### Windows Processes

- services.exe
- svchost.exe
- powershell.exe
- rundll32.exe
- regsvr32.exe

### Windows Services

- Service Control Manager
- Driver Loading
- Service Hardening
- Windows Services

### Windows Security

- PrintNightmare
- Driver Signing
- Point-and-Print
- Service Security
- Privilege Escalation
