# 05 - Hunting Evil with Sigma - Chainsaw 

## Executive Summary

This investigation focused on offline Windows event log hunting using Chainsaw and Sigma rules. By executing a Sigma detection rule against an exported EVTX file, the investigation demonstrated how PowerShell Script Block Logging can be analyzed to identify Windows Defender exclusion abuse and detect defense evasion techniques without relying on a SIEM platform.

## Investigation Objectives 

- Perform offline Windows event log hunting using Chainsaw.
- Execute Sigma detection rules against EVTX files.
- Detect PowerShell Script Block activity associated with Defender exclusions.
- Identify suspicious Windows Defender exclusion paths.
- Understand how attackers abuse Defender exclusions for defense evasion.
- Map observed behavior to MITRE ATT&CK.

## Challenge Context

The investigation was initiated after security analysts suspected that Windows Defender exclusions had been modified to allow malware to evade endpoint protection. Because the investigation relied solely on exported Windows event logs, analysts were tasked with using Chainsaw and Sigma rules to identify suspicious PowerShell activity associated with Defender exclusion modifications.

The investigation focused on correlating PowerShell Script Block Logging (Event ID 4104), Sigma detections, and Defender configuration changes to identify excluded directories that could facilitate malware execution while bypassing Windows Defender scanning.

## Background 

### What is Chainsaw? 

Chainsaw is an offline Windows event log hunting framework designed to rapidly analyze EVTX files using Sigma detection rules. It enables analysts to perform large-scale forensic investigations without requiring a SIEM platform by applying standardized detection logic directly against exported Windows event logs.

### Why Use Chainsaw? 

Chainsaw enables investigators to perform rapid offline threat hunting across Windows event logs while maintaining compatibility with Sigma detection rules. It is particularly valuable during incident response, forensic investigations, and malware analysis where direct access to centralized logging infrastructure is unavailable.

### Sigma-based Event Hunting

Chainsaw uses Sigma rules to identify suspicious activity recorded within Windows event logs. Detection logic is translated internally through mapping files that associate Sigma fields with native Windows event log fields, enabling consistent detections across multiple Windows logging sources.

### PowerShell Script Block Logging 

PowerShell Script Block Logging (Event ID 4104) records executed PowerShell commands before they are interpreted by the PowerShell engine. These events provide high-value forensic evidence for detecting attacker behavior, credential theft, defense evasion, persistence mechanisms, and malicious automation.

### Windows Defender Exclusion Abuse 

Attackers frequently modify Windows Defender exclusion lists to prevent malicious files, payloads, or staging directories from being scanned. Monitoring exclusion-related PowerShell commands provides valuable visibility into defense evasion attempts that may otherwise remain undetected.

## MITRE ATT&CK Mapping (Background)

| Technique | ATT&CK ID |
|-----------|-----------|
| PowerShell | T1059.001 |
| Indicator Removal | T1070 |
| Impair Defenses | T1562.001 |

## Data Sources 

| Source | Purpose |
|---------|----------|
| Windows PowerShell Operational Log | PowerShell Script Block Logging |
| Offline EVTX Log | Event log hunting |
| Sigma Rule | Detection logic |
| Chainsaw | Offline Sigma execution |
| Mapping File | Sigma field translation |

## Investigation Scope

The investigation focused on identifying Windows Defender exclusion abuse through offline analysis of Windows event logs. Particular emphasis was placed on detecting PowerShell commands that modified Defender exclusion settings and identifying directories intentionally excluded from antivirus scanning.

## Investigation Methodology

The investigation followed a structured methodology:

1. Review the Sigma detection rule.
2. Execute the rule using Chainsaw.
3. Analyze PowerShell Script Block events.
4. Review Defender exclusion commands.
5. Identify excluded directories.
6. Validate the detection results. 

## Investigation Overview 

The investigation combined offline Windows event log analysis with Sigma-based detection engineering to identify Windows Defender exclusion abuse. By executing a Sigma rule using Chainsaw against an exported EVTX file, analysts identified PowerShell commands responsible for modifying Defender exclusions and extracted the suspicious directory added to the exclusion list.

## Investigation Exercise 

### Objective:

Execute the provided Sigma rule using Chainsaw and identify the directory added to the Windows Defender exclusion list.

### Question:

Execute the following Sigma rule:

`posh_ps_win_defender_exclusions_added.yml`

against

`lab_events_5.evtx`

Identify the excluded directory.

**Answer format**

Directory path.

### Solution:

`C:\document\virus\`

## Investigation Query #1 

### Purpose:

Execute the Sigma rule against the offline EVTX log using Chainsaw.

### Command:

cd C:\Tools\chainsaw\
.\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_5.evtx -s C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_win_defender_exclusions_added.yml --mapping .\mappings\sigma-event-logs-all.yml

### Results:

| Field | Value |
|-------|-------|
| Tool | `Chainsaw` |
| Sigma Rule | `posh_ps_win_defender_exclusions_added.yml` |
| Event ID | `4104` |
| Detection | Windows Defender Exclusion Modification |

### Query Analysis:

Chainsaw executed the Sigma detection rule against the offline EVTX log using the appropriate mapping file. The resulting detections identified PowerShell Script Block events containing commands that modified Windows Defender exclusion settings.

## Investigation Findings

Execution of the Sigma rule using Chainsaw successfully identified PowerShell Script Block events associated with Windows Defender exclusion modifications. Analysis of the returned events revealed the execution of the `Set-MpPreference -ExclusionPath` command and identified `C:\document\virus\` as the excluded directory. The observed behavior is consistent with a defense evasion technique intended to prevent Windows Defender from scanning attacker-controlled files.

## Investigation Workflow 

The investigation followed a structured workflow:

1. Review the Sigma rule `posh_ps_win_defender_exclusions_added.yml`.
2. Execute the Sigma rule using Chainsaw:
```powershell
.\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_5.evtx -s C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_win_defender_exclusions_added.yml --mapping .\mappings\sigma-event-logs-all.yml
```
3. Review PowerShell Script Block events (Event ID 4104).
4. Identify execution of:
```
Set-MpPreference -ExclusionPath
```
5. Extract the excluded directory:
```
C:\document\virus\
```
6. Validate that the observed behavior represents Windows Defender exclusion abuse.

## Detection Engineering Concepts

### Sigma Rule Execution 

Sigma rules provide standardized detection logic that can be executed directly by Chainsaw against offline Windows event logs. This enables analysts to validate detections without requiring a SIEM platform while maintaining consistent detection behavior across different investigation environments.

### Offline EVTX Hunting 

Offline EVTX hunting allows investigators to analyze exported Windows event logs independently of the original endpoint. This capability is particularly valuable during incident response and forensic investigations where centralized logging or endpoint access is unavailable.

### Mapping Files

Chainsaw relies on Sigma mapping files to translate standardized Sigma fields into their corresponding Windows event log fields. Correct mapping ensures that Sigma rules evaluate the appropriate event attributes and produce accurate detections across different Windows logging sources.

### Defender Exclusion Monitoring 

Monitoring modifications to Windows Defender exclusions provides valuable visibility into defense evasion techniques. Commands such as `Set-MpPreference -ExclusionPath` frequently indicate attempts to exclude malware, staging directories, or attacker-controlled files from antivirus scanning.

## Detection Logic

### PowerShell Script Block Logging

PowerShell Script Block Logging (Event ID 4104) records executed PowerShell commands and provides detailed visibility into administrative and attacker activity. Monitoring these events enables analysts to identify malicious PowerShell execution, including commands that modify Windows Defender settings.

### Defender Exclusion Modification

The PowerShell cmdlet `Set-MpPreference -ExclusionPath` modifies the list of directories excluded from Windows Defender scanning. While commonly used by administrators, unauthorized execution of this command is frequently associated with malware deployment and defense evasion techniques. 

### Suspicious Excluded Directory 

Analysis of the PowerShell Script Block event identified the excluded directory `C:\document\virus\`. Windows Defender exclusions are frequently abused by attackers to prevent malware, payloads, tools, or staging directories from being scanned by endpoint protection. The directory name itself strongly suggests malicious intent, making the observed exclusion a high-confidence indicator of defense evasion and unauthorized Windows Defender configuration changes.

## IOC Summary

| IOC Type | Value |
|-----------|-------|
| Tool | Chainsaw |
| Sigma Rule | `posh_ps_win_defender_exclusions_added.yml` |
| Event Log | `lab_events_5.evtx` |
| Event ID | `4104` |
| PowerShell Command | `Set-MpPreference -ExclusionPath` |
| Excluded Directory | `C:\document\virus\` |

## Placeholder Screenshots

Figure 1 - Event 4688 showing suspicious PowerShell command
Figure 2 - Chainsaw execution against lab_events_5.evtx
Figures 3 - Detection showing ExclusionPath C:\document\virus\
Figure 4 - Second detection showing exclusion extension .exe

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | Windows Defender exclusion abuse |
| Execution | PowerShell | T1059.001 | Execution of Defender exclusion commands |
| Defense Evasion | Indicator Removal on Host | T1070 | Modification of Defender configuration |

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Offline Threat Hunting | Chainsaw enables fast and efficient offline hunting across Windows EVTX logs without requiring a SIEM platform. |
| Sigma-based Detection | Sigma rules can be executed directly against Windows event logs, providing standardized and reusable detection logic. |
| Defense Evasion Detection | Windows Defender exclusion modifications represent high-confidence indicators of defense evasion and should be closely monitored. |
| PowerShell Visibility | PowerShell Script Block Logging (Event ID 4104) provides detailed visibility into executed commands, making it invaluable for detecting malicious PowerShell activity. |
| Sigma Mapping | Mapping files are essential because Chainsaw relies on them to correctly translate Sigma fields into Windows event log fields and produce accurate detections. |

## Conclusion

This investigation demonstrated how Chainsaw and Sigma rules can be combined to perform efficient offline threat hunting against Windows event logs. By analyzing PowerShell Script Block Logging, analysts successfully identified unauthorized Windows Defender exclusion modifications and extracted the suspicious directory `C:\document\virus\`. The investigation highlights the effectiveness of Sigma-based offline detection engineering for identifying defense evasion techniques without relying on a traditional SIEM environment.

