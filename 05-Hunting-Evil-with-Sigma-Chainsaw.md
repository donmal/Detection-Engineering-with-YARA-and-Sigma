# 05 - Hunting Evil with Sigma - Chainsaw 

## Executive Summary

This investigation focused on offline Windows event log hunting using Chainsaw and Sigma rules. By executing a Sigma detection rule against an exported EVTX file, the investigation demonstrated how PowerShell Script Block Logging can be analyzed to identify Windows Defender exclusion abuse and detect defense evasion techniques without relying on a SIEM platform.

The investigation identified a PowerShell command referencing **Set-MpPreference -ExclusionPath** and the directory **C:\document\virus\**. The observed activity is consistent with a potential attempt to weaken endpoint protection by excluding a directory from Microsoft Defender scanning.

## Investigation Objectives 

- Perform offline Windows event log hunting using Chainsaw.
- Execute Sigma detection rules against EVTX files.
- Detect PowerShell Script Block activity associated with Defender exclusions.
- Identify suspicious Windows Defender exclusion paths.
- Understand how attackers abuse Defender exclusions for defense evasion.
- Map observed behavior to MITRE ATT&CK.

## Investigation Context

This investigation was conducted in a controlled Hack The Box Academy environment using an exported Windows event log and a provided Sigma detection rule. The objective was to identify PowerShell activity associated with Microsoft Defender exclusion configuration and extract any suspicious excluded directory paths.

The investigation focused on analyzing PowerShell Script Block Logging (Event ID 4104), Sigma detections, and Defender configuration commands to identify excluded directories that could facilitate malware execution while bypassing Windows Defender scanning.

## Background 

### What is Chainsaw? 

Chainsaw is an offline Windows event log hunting framework designed to rapidly analyze EVTX files using Sigma detection rules. It enables analysts to perform large-scale forensic investigations without requiring a SIEM platform by applying standardized detection logic directly against exported Windows event logs.

### Why Use Chainsaw? 

Chainsaw enables investigators to perform rapid offline threat hunting across Windows event logs while maintaining compatibility with Sigma detection rules. It is particularly valuable during incident response, forensic investigations, and malware analysis where direct access to centralized logging infrastructure is unavailable.

### Sigma-based Event Hunting

Chainsaw uses Sigma rules to identify suspicious activity recorded within Windows event logs. Detection logic is translated internally through mapping files that associate Sigma fields with native Windows event log fields, enabling rule evaluation across multiple Windows logging sources.

### PowerShell Script Block Logging 

PowerShell Script Block Logging (Event ID 4104) PowerShell script block content processed by the PowerShell engine when the relevant logging is available and enabled.

These events provide high-value forensic evidence for detecting attacker behavior, credential theft, defense evasion, persistence mechanisms, and malicious automation.

However, an Event ID 4104 record alone does not prove that every operation described in the script block completed successfully.

### Windows Defender Exclusion Abuse 

Attackers frequently modify Windows Defender exclusion lists to prevent malicious files, payloads, or staging directories from being scanned. Monitoring exclusion-related PowerShell commands provides valuable visibility into defense evasion attempts that may otherwise remain undetected.

## MITRE ATT&CK Mapping (Background)

| Technique | ATT&CK ID |
|-----------|-----------|
| PowerShell | T1059.001 |
| Impair Defenses | T1562.001 |

T1059.001 and T1562.001 are relevant to the documented PowerShell activity and Defender exclusion modification. T1070 should be removed because changing Defender exclusions is not equivalent to deleting or modifying forensic indicators on the host.

## Data Sources 

| Source | Purpose |
|---------|----------|
| Windows PowerShell Operational Log | PowerShell Script Block Logging |
| Offline EVTX Log | Event log hunting |
| Sigma Rule | Detection logic |
| Chainsaw | Offline Sigma execution |
| Mapping File | Sigma field translation |

## Investigation Scope

The investigation focused on identifying Windows Defender exclusion abuse through offline analysis of Windows event logs. Particular emphasis was placed on detecting PowerShell commands that modified Defender exclusion settings and identifying directories referenced in Defender exclusion configuration commands.

## Investigation Methodology

The investigation followed a structured methodology:

1. Review the Sigma detection rule.
2. Execute the rule using Chainsaw.
3. Analyze PowerShell Script Block events.
4. Review Defender exclusion commands.
5. Identify excluded directories.
6. Interpret the detection results and assess the evidence for potential defense evasion.

## Investigation Overview 

The investigation combined offline Windows event log analysis with Sigma-based detection engineering to identify Windows Defender exclusion abuse.

By executing a Sigma rule using Chainsaw against an exported EVTX file, analysts identified PowerShell commands associated with Defender exclusion configuration and extracted the suspicious directory added to referenced in the exclusion list.

The detection provides evidence of a suspicious configuration command, while confirmation that the exclusion was successfully applied would require additional Defender configuration or event evidence.

## Defender Exclusion Investigation

**Analysis Objective**: Apply a Sigma rule to the provided EVTX log using Chainsaw and investigate PowerShell script blocks containing Windows Defender exclusion-related commands.

Investigation Artifacts:

C:\Events\YARASigma\lab_events_5.evtx
C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_win_defender_exclusions_added.yml

## 1. Sigma-based Hunting with Chainsaw

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
| PowerShell Command | 	Set-MpPreference -ExclusionPath |
| Excluded Directory | 	C:\document\virus\ |


### Analysis:

Chainsaw executed the Sigma detection rule against the offline EVTX log using the appropriate mapping file. The resulting detections identified PowerShell Script Block events containing commands that modified Windows Defender exclusion settings.

The matched activity included the **Set-MpPreference -ExclusionPath** command referencing **C:\document\virus\**. This finding indicates an attempt to configure a Defender exclusion and warrants further investigation into the command's origin, execution context, and resulting endpoint configuration.

## Investigation Findings

Execution of the Sigma rule using Chainsaw successfully identified PowerShell Script Block events associated with Windows Defender exclusion modifications. 

Analysis of the returned events revealed a script block containing the `Set-MpPreference -ExclusionPath` command and identified `C:\document\virus\` as the excluded directory referenced in the command. 

The observed behavior is consistent with a defense evasion technique intended to prevent Windows Defender from scanning attacker-controlled files.

The directory name and exclusion-related command are suspicious in context, but the available evidence does not independently establish that the directory was attacker-controlled or that the exclusion was successfully applied.

## Detection Logic

### PowerShell Script Block Logging

PowerShell Script Block Logging (Event ID 4104) records PowerShell script block content and provides detailed visibility into administrative and attacker activity. 

Monitoring these events enables analysts to identify potentially suspicious PowerShell activity, including commands that modify Windows Defender settings.

### Defender Exclusion Modification

The PowerShell cmdlet `Set-MpPreference -ExclusionPath` modifies the list of directories excluded from Windows Defender scanning. 

More precisely, the **-ExclusionPath** parameter configures excluded paths, while **Set-MpPreference** sets the specified preference values. This should be distinguished from **Add-MpPreference**, which can append exclusions to existing settings.

While commonly used by administrators, unauthorized execution of this command is frequently associated with malware deployment and defense evasion techniques. 

### Suspicious Excluded Directory 

Analysis of the PowerShell Script Block event identified the excluded directory `C:\document\virus\`. 

Windows Defender exclusions are frequently abused by attackers to prevent malware, payloads, tools, or staging directories from being scanned by endpoint protection. 

The directory path is suspicious in the context of the detected exclusion command, particularly because the folder name contains virus. However, the name alone is insufficient to confirm malicious intent or unauthorized configuration changes. The finding should be correlated with process ownership, user context, and Defender configuration telemetry.

## Investigation Artifacts and Indicators

| IOC Type | Value |
|-----------|-------|
| Tool | Chainsaw |
| Sigma Rule | `posh_ps_win_defender_exclusions_added.yml` |
| Event Log | `lab_events_5.evtx` |
| Event ID | `4104` |
| PowerShell Command | `Set-MpPreference -ExclusionPath` |
| Excluded Directory | `C:\document\virus\` |

**Note**: Chainsaw, the Sigma rule, EVTX file, and Event ID are investigation artifacts or telemetry references, not IOCs. The exclusion command and directory path are the relevant suspicious indicators identified in this analysis.



## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | Windows Defender exclusion abuse — suspected defense evasion through an exclusion-related PowerShell command |
| Execution | PowerShell | T1059.001 | Execution of Defender exclusion commands — PowerShell script block containing the exclusion command |

**Mapping assessment**: T1562.001 is the strongest mapping because the command concerns modification of antivirus exclusion settings. T1059.001 is relevant because the activity was recorded in PowerShell Script Block Logging. Both mappings describe the observed or suspected technique, not independently confirmed successful evasion.

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Offline Threat Hunting | Chainsaw enables fast and efficient offline hunting across Windows EVTX logs without requiring a SIEM platform. |
| Sigma-based Detection | Sigma rules can be applied through compatible tools such as Chainsaw against Windows event logs, providing standardized and reusable detection logic. |
| Defense Evasion Detection | Unexpected Defender exclusion commands are valuable defense evasion indicators, particularly when correlated with suspicious paths, user activity, or other endpoint evidence. |
| PowerShell Visibility | PowerShell Script Block Logging (Event ID 4104) provides detailed visibility into processed script block content, making it invaluable for detecting malicious PowerShell activity. |
| Sigma Mapping | Mapping files are essential because Chainsaw relies on them to correctly translate Sigma fields into Windows event log fields and produce accurate detections. |

## Conclusion

This investigation demonstrated how Chainsaw and Sigma rules can be combined to perform efficient offline threat hunting against Windows event logs. 

By analyzing PowerShell Script Block Logging, analysts successfully identified suspicious Windows Defender exclusion-related PowerShell activity and extracted the referenced directory `C:\document\virus\`. 

The investigation highlights the effectiveness of Sigma-based offline detection engineering for identifying potential defense evasion behavior without relying on a traditional SIEM environment.

The finding provides a useful starting point for further investigation, although confirmation of the final Defender configuration and the intent behind the exclusion would require additional endpoint evidence.
