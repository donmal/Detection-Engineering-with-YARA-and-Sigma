# 07 - Detection Engineering Capstone 

## Executive Summary

This capstone assessment combines two core Detection Engineering disciplines: YARA rule development and Sigma-based threat hunting. The first assessment focuses on improving a YARA rule through static malware analysis, while the second validates Sigma detection logic using Chainsaw against offline Windows event logs. Together, the exercises demonstrate how detection engineering techniques can be applied to identify malware artifacts, PowerShell abuse, and ransomware-related activity using standardized detection logic.

## Assessment Objectives

- Develop and improve YARA detection rules through malware analysis.
- Identify malware-specific artifacts within .NET assemblies.
- Validate YARA rules against malware samples.
- Execute Sigma rules using Chainsaw against offline Windows Event Logs.
- Detect PowerShell activity associated with Shadow Volume Copy deletion.
- Identify indicators commonly associated with ransomware behavior.
- Correlate detection engineering concepts with MITRE ATT&CK techniques.

## Challenge Context

The assessment was designed to evaluate practical detection engineering skills across two complementary scenarios. The first required analysts to inspect a .NET malware sample and improve an existing YARA rule by replacing a missing detection artifact. The second required analysts to execute a Sigma rule using Chainsaw to identify PowerShell activity associated with the deletion of Windows Volume Shadow Copies. Together, both exercises simulate common Detection Engineering tasks involving malware analysis, rule development, and offline log hunting.

## Background

### Capstone Overview

This assessment combines static malware analysis with offline event log hunting to evaluate practical Detection Engineering skills. Analysts are required to inspect malware samples, improve detection rules, execute Sigma-based detections, and validate the resulting findings using Windows event telemetry.

### Assessment Part I – YARA Rule Development

The first assessment focuses on improving an existing YARA rule used to detect the Seatbelt post-exploitation framework. By inspecting the .NET assembly with dnSpy and identifying characteristic class names, the missing detection string is added to the rule to ensure reliable malware detection.

### Assessment Part II – Sigma Hunting with Chainsaw

The second assessment focuses on detecting PowerShell activity associated with Windows Volume Shadow Copy deletion. Using Chainsaw and Sigma rules, analysts perform offline threat hunting against Windows Event Logs to identify ransomware-related behavior and extract the associated ScriptBlock ID.

## MITRE ATT&CK Mapping (Background)

| Technique | ATT&CK ID |
|-----------|-----------|
| PowerShell | T1059.001 |
| Inhibit System Recovery | T1490 |
| Indicator Removal | T1070 |
| Malware | T1587 |

## Tools Used

| Tool | Purpose |
|------|---------|
| YARA | Malware detection |
| dnSpy | .NET assembly analysis |
| Chainsaw | Offline EVTX hunting |
| Sigma | Detection rules |
| Windows PowerShell | Event analysis |

## Data Sources

| Source | Purpose |
|---------|----------|
| Seatbelt.exe | Malware analysis |
| seatbelt.yar | YARA rule validation |
| Windows EVTX Logs | Event investigation |
| Sigma Rule | PowerShell detection |
| Chainsaw | Offline event analysis |

## Assessment Scope

The assessment focuses on validating practical detection engineering skills through malware analysis and offline Windows event log hunting. Activities include YARA rule development, .NET assembly inspection, Sigma rule execution, and identification of ransomware-related PowerShell behavior.

## Assessment Methodology

The assessment followed a structured methodology:

1. Review the supplied detection rule.
2. Analyze the associated malware sample or event logs.
3. Identify missing detection artifacts.
4. Improve or execute the detection rule.
5. Validate the generated detection.
6. Confirm the required assessment answer.

## Assessment Overview

The assessment consists of two independent investigations designed to evaluate complementary Detection Engineering skills. The first investigation validates static malware detection through YARA rule development, while the second validates behavioral detection using Sigma rules executed with Chainsaw against offline Windows Event Logs.

### Assessment Part I – YARA Rule Development

Seatbelt is a .NET-based post-exploitation framework developed as part of the GhostPack toolkit. It is commonly used for host enumeration, privilege assessment, credential discovery, and situational awareness during post-exploitation activities. Detection frequently relies on identifying unique .NET class names and other malware-specific artifacts.

## Background

## Investigation Exercise

### Objective

Update the existing YARA rule so that it correctly detects the Seatbelt malware sample.

### Question
Complete the missing variable `$class2` inside `seatbelt.yar` so that the rule successfully detects `Seatbelt.exe`.

### Solution

`LsaWrapper`

## Investigation Query #1

### Purpose

Identify the missing .NET class required to complete the YARA rule.

### Command

``` cmd
yara64.exe .\seatbelt.yar C:\Samples\YARASigma\
```
### Results

| Field | Value |
|-------|-------|
| Malware Sample | `Seatbelt.exe` |
| Missing Class | `LsaWrapper` |
| Detection Status | Successful |

### Query Analysis

The updated YARA rule successfully detected the Seatbelt malware sample after replacing the placeholder with the class name LsaWrapper. Because the rule required four matching strings, adding the missing class satisfied the detection condition.

## Investigation Findings

Static analysis of the .NET assembly identified `LsaWrapper` as the missing malware-specific class required by the YARA rule. After updating the rule, successful validation confirmed that the detection logic accurately identified the Seatbelt sample.

## Detection Engineering Concepts

### .NET Assembly Analysis 

Many modern malware families are developed using the Microsoft .NET framework. Tools such as dnSpy allow analysts to inspect compiled assemblies, enumerate namespaces, classes, methods, and embedded strings, making it possible to identify stable artifacts suitable for YARA detection.

### YARA Rule Development 

YARA rules are developed by selecting unique malware characteristics such as strings, imported libraries, .NET metadata, PE headers, file structure, or other distinguishing artifacts. Well-designed rules balance detection accuracy with a low false-positive rate by relying on malware-specific indicators rather than generic strings.

### Malware-specific String Selection

Selecting malware-specific strings is one of the most important aspects of YARA rule development. Characteristic class names such as `LsaWrapper`, together with other unique artifacts, provide reliable indicators that distinguish malware from legitimate software while improving detection precision.

## Detection Logic

### PE Validation 

The YARA rule verifies that the analyzed file is a valid Portable Executable (PE) by checking the `MZ` header and the `PE` signature. These checks prevent the rule from matching non-executable files before additional detection logic is evaluated.

### .NET Detection (BSJB) 

The `BSJB` string is a characteristic marker found within .NET assemblies. Detecting this value allows the rule to verify that the analyzed sample contains a Common Language Runtime (CLR) metadata structure before evaluating .NET-specific artifacts.

### Multi-string Rule Matching (“4 of them”)

The condition `4 of them` requires that at least four predefined strings be present before the rule generates a match. This threshold increases detection reliability by ensuring that multiple malware-specific indicators are observed simultaneously, thereby reducing false positives.

## Assessment Part II – Sigma Hunting with Chainsaw

Windows Volume Shadow Copies provide recovery snapshots that can be used to restore files following accidental deletion or ransomware encryption. Attackers frequently remove these snapshots before encrypting data to prevent recovery, making Shadow Copy deletion a valuable behavioral detection opportunity.

## Background

## Investigation Exercise

### Objective

Identify the ScriptBlock ID associated with Shadow Volume Copy deletion.

### Question

Execute the Sigma rule against the supplied EVTX log and identify the ScriptBlock ID associated with Shadow Volume Copy deletion.

### Solution

`faaeba08-01f0-ba48-bd65-b24afd28`

## Investigation Query #2

### Purpose 

Detect PowerShell activity associated with Shadow Volume Copy deletion.

### Command 

```cmd
.\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_6.evtx -s C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_susp_win32_shadowcopy.yml --mapping .\mappings\sigma-event-logs-all.yml
```

### Results 

| Field | Value |
|-------|-------|
| Tool | `Chainsaw` |
| Event ID | `4104` |
| Detection | Shadow Copy Deletion |
| ScriptBlock ID | `faaeba08-01f0-ba48-bd65-b24afd28` |

### Query Analysis

The Sigma rule identified PowerShell Script Block Logging events containing commands that invoked the Delete() method against Win32_ShadowCopy. Review of the event data revealed the associated ScriptBlock ID.

## Investigation Findings

Chainsaw successfully executed the Sigma rule against the offline Windows Event Logs and identified PowerShell activity consistent with Shadow Volume Copy deletion. The recovered ScriptBlock ID confirmed execution of commands commonly associated with ransomware attempts to inhibit system recovery.

## Detection Engineering Concepts

### Offline EVTX Hunting 

Offline EVTX hunting enables analysts to investigate Windows Event Logs without requiring a live system or SIEM. By analyzing exported event log files, investigators can reconstruct attacker activity, validate detections, and perform incident response even when the original host is unavailable.

### Sigma Rule Execution 

Sigma rules provide platform-independent detection logic that can be executed using tools such as Chainsaw. Applying Sigma rules directly to Windows Event Logs allows analysts to rapidly identify suspicious behavior without manually developing complex detection queries.

### PowerShell Script Block Logging 

PowerShell Script Block Logging (Event ID 4104) records the actual PowerShell code executed on a system. This telemetry provides valuable visibility into attacker commands, making it one of the most effective data sources for detecting PowerShell-based attacks.

### Chainsaw Hunting

Chainsaw is an offline threat hunting framework capable of applying Sigma detection rules directly against Windows Event Logs. By combining Sigma rules with field mapping files, Chainsaw enables efficient investigation of EVTX data without relying on a centralized SIEM platform.

## Detection Logic

### PowerShell Script Block Detection 

The Sigma rule monitors PowerShell Script Block Logging (Event ID 4104) for commands associated with Shadow Volume Copy manipulation. Inspection of ScriptBlock content provides direct visibility into potentially malicious PowerShell activity.

### Shadow Copy Deletion Detection 

Commands invoking `Win32_ShadowCopy` together with the `Delete()` method represent strong indicators of attempts to remove Windows Volume Shadow Copies. Because ransomware frequently performs this action before encrypting files, such behavior should be treated as high-priority during investigations.

### ScriptBlock ID Correlation

The ScriptBlock ID uniquely identifies a PowerShell script execution event. Correlating this identifier with ScriptBlock content enables analysts to attribute suspicious PowerShell activity to specific events and simplifies incident reconstruction.

## IOC Summary

| IOC Type | Value |
|-----------|-------|
| Malware Sample | `Seatbelt.exe` |
| Missing Class | `LsaWrapper` |
| Detection Tool | `YARA` |
| Sigma Rule | `posh_ps_susp_win32_shadowcopy.yml` |
| Event ID | `4104` |
| Detection | Shadow Volume Copy Deletion |
| ScriptBlock ID | `faaeba08-01f0-ba48-bd65-b24afd28` |

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Execution | PowerShell | `T1059.001` | PowerShell Script Block activity |
| Impact | Inhibit System Recovery | `T1490` | Shadow Volume Copy deletion |
| Defense Evasion | Indicator Removal on Host | `T1070` | Removal of recovery artifacts |
| Resource Development | Develop Capabilities: Malware | `T1587` | YARA detection of Seatbelt |

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Static Malware Analysis | .NET class names provide reliable artifacts for YARA rule development. |
| Rule Validation | Updating a single malware-specific artifact can significantly improve detection accuracy. |
| YARA Detection | Combining multiple indicators strengthens detection logic while reducing false positives. |
| Offline Threat Hunting | Chainsaw enables efficient execution of Sigma rules against offline Windows Event Logs. |
| PowerShell Visibility | Event ID 4104 provides detailed visibility into executed PowerShell commands and attacker behavior. |
| Ransomware Detection | Shadow Volume Copy deletion is a high-confidence indicator of ransomware activity and should be prioritized during investigations. |

## Conclusion 

This capstone assessment demonstrated the complementary roles of YARA rule development and Sigma-based threat hunting within Detection Engineering. Through static malware analysis and offline Windows event log investigation, analysts successfully improved a YARA rule for detecting the Seatbelt framework and identified PowerShell activity associated with Shadow Volume Copy deletion. Together, these exercises illustrate how multiple detection engineering techniques can be combined to improve malware detection, behavioral analysis, and incident response capabilities.
