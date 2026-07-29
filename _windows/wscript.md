---
title: wscript.exe
layout: post
permalink: /windows/wscript/
group: Processes
---

## Overview

wscript.exe is the graphical Windows Script Host (WSH) executable.

It executes:

- VBScript (.vbs, .vbe)
- JScript (.js, .jse)
- Windows Script Files (.wsf)

Unlike cscript.exe, which provides a console-based interface, wscript.exe executes scripts in a windowed environment and can display dialogs and message boxes.

### Expected Characteristics

#### Expected Locations

- %SYSTEMROOT%\System32\wscript.exe
- %SYSTEMROOT%\SysWOW64\wscript.exe

#### Expected Parents

Common examples include:

- explorer.exe
- msiexec.exe
- Approved enterprise tooling
- Trusted installers

#### Typical Profile

- Intermittent on workstations
- Rare on hardened servers
- Commonly associated with legacy automation
- Frequently abused in phishing execution chains

## Why This Matters

Attackers have abused Windows Script Host for decades.

wscript.exe remains useful because it can:

- Execute scripts directly from disk
- Launch second-stage payloads
- Retrieve remote content
- Chain into other LOLBins
- Modify system configuration
- Establish persistence

Common attack chains involve:

- Email attachments
- Downloaded scripts
- Archive extraction
- User execution
- Script-based persistence

### Investigation Objective

Determine:

- What script was executed
- How the script reached the host
- Whether execution was user-driven
- Whether persistence or staging occurred
- Whether additional payloads were launched

## Normal Behaviour

### Characteristics

#### Path

- C:\Windows\System32\wscript.exe
- C:\Windows\SysWOW64\wscript.exe

#### Signature

- Microsoft Windows Publisher

#### Parent Processes

Common examples include:

- explorer.exe
- msiexec.exe
- Enterprise deployment tooling
- Approved automation frameworks

#### Children

Usually none.

Child processes should align with known administrative workflows.

#### Script Types

Common examples include:

- .vbs
- .js
- .wsf

### Typical Activity

- Legacy logon scripts
- Desktop automation
- Vendor management tooling
- Administrative utilities
- Installer custom actions

### Expected Behavioural Characteristics

Legitimate WSH usage typically:

- References known scripts
- Uses trusted paths
- Appears consistently across hosts
- Aligns with administrative activity

## Abuse Patterns

### Suspicious Script Locations

Investigate scripts launched from:

- %TEMP%
- %APPDATA%
- %LOCALAPPDATA%
- %PROGRAMDATA%
- %PUBLIC%
- Downloads
- Network shares

Most malicious WSH activity originates from user-controlled or transient locations. 【1-52245b】

### Unexpected Parent Processes

Investigate wscript.exe launched by:

- Browsers
- Office applications
- PDF readers
- Archive tools
- mshta.exe
- rundll32.exe
- Unknown binaries

These relationships are frequently observed during phishing and malware delivery.

### Child Process Abuse

Investigate wscript.exe spawning:

    powershell.exe

    cmd.exe

    mshta.exe

    rundll32.exe

    regsvr32.exe

    cscript.exe

    unsigned executables

This commonly indicates staged execution.

### Obfuscated Scripts

Investigate:

- Long command lines
- Encoded strings
- Base64 content
- Heavy escaping
- Dynamic string construction

The more effort spent hiding script contents, the more scrutiny the script deserves.

### COM Object Abuse

Look for:

    WScript.Shell

    ADODB.Stream

    MSXML2.XMLHTTP

These are frequently used to:

- Download payloads
- Execute commands
- Write files
- Launch additional stages

### Fileless Execution

Investigate:

- Registry-stored scripts
- Environment-variable expansion
- Remote script retrieval
- Dynamic payload construction

The absence of a traditional payload does not imply benign behaviour.

### Persistence Activity

Review execution that:

- Modifies Run keys
- Creates scheduled tasks
- Registers COM objects
- Creates WMI subscriptions

WSH is commonly used during persistence setup.

## Detection Opportunities

### Script Execution Monitoring

Monitor:

- Script file execution
- Script file creation
- Script file downloads
- Script file prevalence

The script itself often provides more value than the host process.

### Parent Process Analytics

Investigate:

- Office → wscript.exe
- Browser → wscript.exe
- PDF Reader → wscript.exe

These process chains frequently indicate malicious user execution.

### Child Process Analytics

Monitor for:

- PowerShell
- Command Prompt
- LOLBins
- Unsigned executables

spawned by wscript.exe.

Unexpected child processes frequently provide high-confidence signals.

### Command-Line Analytics

Investigate:

- Encoded content
- Obfuscation
- Remote content references
- Script chaining

Command lines often reveal execution intent.

### COM Object Monitoring

Useful pivots include:

- WScript.Shell
- ADODB.Stream
- MSXML2.XMLHTTP

These are commonly used by malicious scripts.

### Hunting Opportunities

Useful hunting pivots include:

- Rare scripts
- User-writable script locations
- Script prevalence
- LOLBin chaining
- Office-to-WSH execution
- Browser-to-WSH execution

## False Positives

Legitimate WSH activity still exists in many environments.

### Common Legitimate Scenarios

Examples include:

- Vendor utilities
- Login scripts
- Startup automation
- Installer helper scripts
- Administrative tooling

### Validation Questions

Check:

- Script path
- Script publisher
- Parent process
- Host prevalence
- User activity

A legitimate script usually has a known business purpose and consistent deployment history.

### Estate Context

Legitimate scripts are often:

- Widely deployed
- Predictably named
- Centrally managed
- Stored in trusted locations

## Hardening Recommendations

### Reduce Reliance on Legacy Scripts

Identify:

- Legacy login scripts
- Obsolete automation
- Unmaintained tooling

Reducing WSH usage makes malicious activity easier to identify.

### Application Control

Consider:

- WDAC
- AppLocker
- Application allow-listing

Restrict unauthorised script execution.

### Restrict User-Writable Script Execution

Reduce execution opportunities from:

- AppData
- Temp
- Downloads
- Public directories

Many malicious scripts depend on these paths.

### Monitor Script Host Activity

Maintain visibility into:

- wscript.exe
- cscript.exe
- powershell.exe
- mshta.exe

Attackers frequently chain these tools together.

### Script Governance

Maintain inventories of:

- Approved scripts
- Administrative scripts
- Login scripts
- Deployment scripts

Unknown scripts should be investigated.

### Defensive Validation

Regularly test:

- Script execution detections
- WSH visibility
- LOLBin detections
- Parent-child process analytics

## Triage Checklist

### Identity and Integrity

- Verify image path is System32 or SysWOW64
- Verify Microsoft signature
- Validate filename
- Identify script type

### Lineage and Behaviour

- Review parent process
- Review command line
- Review child processes
- Check for LOLBin chaining

### Script Context

- Review script contents
- Review script timestamps
- Review script origin
- Compare prevalence across hosts

### Scope and Correlation

- Review email activity
- Review browser activity
- Review downloads
- Review archive extraction
- Review related alerts

### Escalation Considerations

Escalate when:

- User-writable execution paths are involved
- Obfuscation is present
- Child-process abuse is identified
- Persistence activity is observed

## ATT&CK References

- T1059 - Command and Scripting Interpreter
- T1204 - User Execution
- T1547 - Boot or Logon Autostart Execution

## Related Topics

### Windows Processes

- cscript.exe
- powershell.exe
- mshta.exe
- regsvr32.exe
- rundll32.exe

### Windows Script Host

- VBScript
- JScript
- WSH
- Script Execution

### MITRE ATT&CK

- T1059 - Command and Scripting Interpreter
- T1204 - User Execution
- T1547 - Boot or Logon Autostart Execution
