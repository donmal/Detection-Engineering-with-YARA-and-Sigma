# 04 - Developing Sigma Rules 

## Executive Summary 

This investigation focused on developing and operationalizing Sigma detection rules by translating platform-independent detection logic into executable PowerShell queries. Through Sigma rule conversion, Windows Defender event analysis, and offline EVTX investigation, the investigation demonstrated how Sigma detections can be validated against Windows event logs to identify malicious artifacts and improve detection engineering workflows.

## Investigation Objectives 

- Understand the purpose and structure of Sigma detection rules.
- Translate Sigma rules into executable PowerShell queries using `sigmac`.
- Analyze Windows Defender events within offline EVTX logs.
- Identify malicious artifacts reported by Microsoft Defender.
- Validate Sigma detection logic against Windows event logs.
- Map observed behavior to MITRE ATT&CK.

## Challenge Context

The investigation was initiated after a SOC analyst received an offline Windows event log containing Microsoft Defender detections. Rather than manually reviewing thousands of events, analysts were tasked with translating an existing Sigma rule into PowerShell and validating the generated detection logic against the EVTX file.

Using `sigmac`, PowerShell, and Windows Defender event telemetry, the investigation focused on identifying the malicious driver detected within the event log and demonstrating how Sigma rules can be converted into practical hunting queries.

## Background 

### What is Sigma? 

Sigma is an open and platform-independent rule format used to describe log-based detection logic. Similar to how YARA detects malware, Sigma provides a standardized method for describing suspicious events that can later be translated into queries for SIEM platforms, EDR products, or PowerShell.

### Why Sigma Rules Matter? 

Sigma enables organizations to write detection logic once and translate it into multiple query languages without rewriting the detection for each security platform. This portability significantly improves detection engineering, promotes rule sharing, and accelerates threat hunting across heterogeneous environments.

### Sigma Rule Translation 

Sigma rules are written in YAML and must be translated into platform-specific query languages before execution. Utilities such as `sigmac` convert Sigma rules into PowerShell, Splunk SPL, Elastic KQL, Microsoft Sentinel KQL, and many other supported formats, allowing analysts to validate detections across multiple environments.

### Windows Defender Event Analysis

Microsoft Defender generates Windows Security events describing malware detections, quarantined files, malicious drivers, and remediation actions. Analyzing these events provides valuable insight into endpoint security incidents and enables investigators to validate Sigma detection logic against real-world telemetry.

### Offline EVTX Investigation 

Offline EVTX analysis allows investigators to examine Windows event logs without requiring access to the original endpoint. This approach is frequently used during incident response, malware analysis, and forensic investigations where only exported event logs are available.

## MITRE ATT&CK Mapping (Background)

| Technique | ATT&CK ID |
|-----------|-----------|
| Indicator Development | T1587.001 |
| Malware | T1587 |
| Windows Event Logging | T1562 |

## Data Sources 

| Source | Purpose |
|---------|----------|
| Windows Defender Events | Malware detection telemetry |
| Offline EVTX Log | Event log analysis |
| Sigma Rule | Detection logic |
| PowerShell | Rule execution |
| sigmac | Sigma rule translation |

## Investigation Scope 

The investigation focused on translating Sigma detection logic into executable PowerShell queries and validating the resulting detections against offline Windows Defender event logs. Particular attention was given to identifying malicious driver activity reported within the EVTX file.

## Investigation Methodology 

The investigation followed a structured workflow:

1. Review the Sigma detection rule.
2. Translate the rule into PowerShell using `sigmac`.
3. Execute the generated query against the offline EVTX log.
4. Review matching Windows Defender events.
5. Identify the reported malicious artifact.
6. Validate the detection results.

## Investigation Exercise 

### Objective:

Translate the provided Sigma rule into PowerShell and execute it against the supplied EVTX log to identify the malicious driver detected by Microsoft Defender.

### Question:

Translate the following Sigma rule:

`C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml`

Execute the translated PowerShell query against:

`C:\Events\YARASigma\lab_events_4.evtx`

Identify the malicious driver detected by Microsoft Defender.

**Answer format**

Driver name.

### Solution:

`mimidrv.sys`

## Investigation Query #1 

### Purpose:

Translate the Sigma rule into an executable PowerShell hunting query.

### Command: 

cd C:\Tools\sigma-0.21\tools
python sigmac -t powershell C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml

### Results:

| Field | Value |
|-------|-------|
| Input Rule | `win_defender_threat.yml` |
| Translation Tool | `sigmac` |
| Output Format | PowerShell |

### Query Analysis:

The sigmac utility translated the platform-independent Sigma rule into an executable PowerShell query compatible with Windows event logs. This translation enabled the detection logic to be validated outside of a SIEM platform.

## Investigation Query #2 

### Purpose:

Execute the translated detection logic against the offline Windows Defender event log.

### Command: 

Get-WinEvent -Path 'C:\Events\YARASigma\lab_events_4.evtx' |
where {($_.ID -eq "1006" -or $_.ID -eq "1116" -or $_.ID -eq "1015" -or $_.ID -eq "1117") } |
select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

### Results: 

| Field | Value |
|-------|-------|
| Event Source | Microsoft Defender |
| Event IDs | `1006`, `1015`, `1116`, `1117` |
| Malicious Driver | `mimidrv.sys` |

### Query Analysis: 

The translated PowerShell query filtered Windows Defender events associated with malware detection and remediation. Review of the event messages revealed that Microsoft Defender had identified the malicious driver mimidrv.sys.

## Investigation Findings 

Translation of the Sigma rule successfully produced a PowerShell query capable of identifying Windows Defender threat events within the supplied EVTX file. Analysis of the matching events revealed multiple Defender detections associated with malware activity, ultimately identifying `mimidrv.sys` as the malicious driver reported by Microsoft Defender. The investigation demonstrated how Sigma rules can be operationalized and validated using offline Windows event logs.

## Investigation Workflow 

The investigation followed a structured workflow:

1. Review the Sigma detection rule `win_defender_threat.yml` describing Windows Defender threat detections.
2. Translate the Sigma rule into an executable PowerShell query using `sigmac`:
```bash
cd C:\Tools\sigma-0.21\tools
python sigmac -t powershell C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml
```
3. Execute the generated PowerShell query against the offline Windows Defender event log:
```powershell
Get-WinEvent -Path 'C:\Events\YARASigma\lab_events_4.evtx' |
where {($_.ID -eq "1006" -or $_.ID -eq "1116" -or $_.ID -eq "1015" -or $_.ID -eq "1117") } |
select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```
4. Review the returned Windows Defender detection events and examine the associated threat messages.
5. Identify the malicious driver reported within the Defender events (`mimidrv.sys`).
6. Validate that the translated Sigma rule successfully detected the malicious artifact within the offline EVTX log.

## Detection Engineering Concepts 

### Sigma Rule Translation 

Sigma rules are platform-independent detection definitions written in YAML that describe suspicious activity using standardized detection logic. Before they can be executed, Sigma rules must be translated into platform-specific query languages using tools such as `sigmac`. This translation enables the same detection logic to be reused across multiple SIEM platforms, EDR solutions, and PowerShell-based investigations while maintaining consistent detection behavior.

### Offline EVTX Hunting 

Offline EVTX hunting allows analysts to investigate exported Windows event logs without requiring access to the original endpoint. By executing translated Sigma queries against EVTX files using PowerShell, investigators can validate detections, reconstruct security events, and identify malicious activity during incident response or forensic investigations.

### Windows Defender Detection 

Microsoft Defender generates detailed event logs describing malware detections, quarantined files, malicious drivers, and remediation actions. Correlating these events with Sigma detection logic enables analysts to identify malicious artifacts, validate detection rules, and improve endpoint threat visibility through standardized detection engineering practices.

## Detection Logic

### Windows Defender Threat Events 

The translated Sigma rule filters Windows Defender events associated with malware detection and remediation by monitoring Event IDs **1006**, **1015**, **1116**, and **1117**. These events provide valuable telemetry describing detected threats, remediation actions, and malware-related activity, making them reliable indicators during Defender investigations.

### Defender Detection Messages 

Windows Defender event messages contain detailed information describing detected threats, including the detection source, affected files, malware names, and remediation status. Reviewing these messages enables analysts to extract high-confidence indicators and identify malicious files, drivers, or tools reported by Microsoft Defender.

### Malicious Driver Identification

Analysis of the translated Defender events identified the malicious driver `mimidrv.sys`. Because malicious drivers frequently provide attackers with kernel-level capabilities for credential theft, privilege escalation, and security bypass, identifying driver-based threats represents an important step in Windows endpoint investigations.

## IOC Summary

| IOC Type | Value |
|-----------|-------|
| Sigma Rule | `win_defender_threat.yml` |
| Event Log | `lab_events_4.evtx` |
| Translation Tool | `sigmac` |
| Output Query | PowerShell (`Get-WinEvent`) |
| Event IDs | `1006`, `1015`, `1116`, `1117` |
| Malicious Driver | `mimidrv.sys` |

## MITRE ATT&CK Mapping 

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Defense Evasion | Indicator Removal on Host | T1070 | Windows Defender detection analysis |
| Resource Development | Develop Capabilities: Malware | T1587 | Sigma detection engineering |
| Resource Development | Develop Capabilities: Malware | T1587.001 | Translation and validation of Sigma rules |

## Placeholder Screenshots

Figure 1 - Sysmon Event ID 10 showing LSASS access
Figure 2 - Event 4776 failed credential validation
Figure 3 - Event details showing TargetUserName and Workstation
Figure 4 - sigmac PowerShell query execution
Figure 5 - Defender output showing mimidrv.sys

## Lessons Learned

•	Sigma rules are portable detections that can be translated into SIEM-specific or PowerShell queries.
•	sigmac helps convert Sigma YAML rules into executable hunting commands.
•	Defender events can reveal malicious files, tools, and drivers.
•	Get-WinEvent is useful for offline EVTX investigation.
•	In this case, the malicious driver detected by Defender was mimidrv.sys.

## Conclusion

This investigation demonstrated how Sigma rules can be translated into executable PowerShell queries and validated against offline Windows event logs. By combining Sigma detection engineering with Windows Defender telemetry, analysts successfully identified the malicious driver `mimidrv.sys` while demonstrating the portability and operational value of Sigma rules across different detection platforms. The investigation also highlighted the importance of validating platform-independent detection logic against real-world telemetry before deploying it within production security environments.
