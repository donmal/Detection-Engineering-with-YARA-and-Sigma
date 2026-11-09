# 04 - Developing Sigma Rules 

## Executive Summary 

This investigation focused on developing and translating Sigma detection rules by translating platform-independent detection logic into executable PowerShell queries. Through Sigma rule conversion, Windows Defender event analysis, and offline EVTX investigation, the investigation demonstrated how Sigma detections can be tested against Windows event logs to identify reported threat artifacts and improve detection engineering workflows.

Using **sigmac** and **Get-WinEvent**, the investigation examined Microsoft Defender threat events within **lab_events_4.evtx** and identified the driver **mimidrv.sys** in the event messages. The analysis demonstrates Sigma rule translation and offline log-based threat hunting within a controlled training environment.

## Investigation Objectives 

- Understand the purpose and structure of Sigma detection rules.
- Translate Sigma rules into executable PowerShell queries using `sigmac`.
- Analyze Windows Defender events within offline EVTX logs.
- Identify malicious artifacts reported by Microsoft Defender.
- Validate Sigma detection logic against Windows event logs.
- Map observed behavior to MITRE ATT&CK where supported by the available evidence.

## Investigation Context

This investigation was conducted in a controlled Hack The Box Academy environment using a provided Sigma rule and an offline Windows event log. The objective was to translate the Sigma detection logic into PowerShell, examine the resulting Microsoft Defender events, and identify the reported malicious driver.

Using `sigmac`, PowerShell, and Windows Defender event telemetry, the investigation focused on identifying the malicious driver detected within the event log and demonstrating how Sigma rules can be converted into practical hunting queries.

## Background 

### What is Sigma? 

Sigma is an open and platform-independent rule format used to describe log-based detection logic. Similar to how YARA detects malware, Sigma provides a standardized method for describing suspicious events that can later be translated into queries for SIEM platforms, EDR products, or PowerShell.

### Why Sigma Rules Matter? 

Sigma enables organizations to write detection logic once and translate it into multiple query languages without rewriting the detection for each security platform. This portability supports detection engineering, promotes rule sharing, and accelerates threat hunting across heterogeneous environments.

### Sigma Rule Translation 

Sigma rules are written in YAML and can be converted into platform-specific queries for execution.. Utilities such as `sigmac` convert Sigma rules into PowerShell, Splunk SPL, Elastic KQL, Microsoft Sentinel KQL, and many other supported formats, allowing analysts to validate detections across multiple environments.

The investigation uses the legacy **sigmac** utility from Sigma 0.21. Translation support and output behavior depend on the Sigma tooling version and available backend.

### Windows Defender Event Analysis

Microsoft Defender generates Windows Event log events describing malware detections, quarantined files, malicious drivers, and remediation actions. Analyzing these events provides valuable insight into endpoint security incidents and enables investigators to validate Sigma detection logic against recorded endpoint telemetry.

### Offline EVTX Investigation 

Offline EVTX analysis allows investigators to examine Windows event logs without requiring access to the original endpoint. This approach is frequently used during incident response, malware analysis, and forensic investigations where only exported event logs are available.

## Data Sources 

| Source | Purpose |
|---------|----------|
| Windows Defender Events | Malware detection telemetry |
| Offline EVTX Log | Event log analysis |
| Sigma Rule | Detection logic |
| PowerShell | Rule query execution |
| sigmac | Sigma rule translation |

## Investigation Scope 

The investigation focused on translating Sigma detection logic into executable PowerShell queries and examining the resulting event matches against offline Windows Defender event logs. Particular attention was given to identifying malicious driver activity reported within the EVTX file.

## Investigation Methodology 

The investigation followed a structured workflow:

1. Review the Sigma detection rule.
2. Translate the rule into PowerShell using `sigmac`.
3. Execute the generated query against the offline EVTX log.
4. Review matching Windows Defender events.
5. Identify the reported malicious artifact.
6. Document the detection results and distinguish Defender-reported threats from independently verified malicious behavior.

## Sigma Rule Translation and Offline EVTX Analysis

**Analysis Objective**: Translate the provided Windows Defender Sigma rule into PowerShell and use the resulting detection logic to inspect an offline EVTX file for reported threats.

**Investigation Artifacts**:

'C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml'
'C:\Events\YARASigma\lab_events_4.evtx'

## 1. Sigma Rule Translation with sigmac

### Purpose:

Translate the Sigma rule into an executable PowerShell hunting query.

### Corrected command structure: 

cd C:\Tools\sigma-0.21\tools
python sigmac -t powershell C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml

### Results:

| Field | Value |
|-------|-------|
| Input Rule | `win_defender_threat.yml` |
| Translation Tool | `sigmac` |
| Output Format | PowerShell |

### Analysis:

The sigmac utility translated the platform-independent Sigma rule into an executable PowerShell query compatible with Windows event logs. This translation enabled the detection logic to be examined and applied outside of a SIEM platform.

The translation demonstrates how Sigma detection logic can be adapted for offline event log investigation. The exact translated query and its supported event fields should be reviewed before execution.

## 2. Offline Windows Defender Event Analysis 

### Purpose:

Execute the translated detection logic against the offline Windows Defender event log.

### Corrected PowerShell syntax: 

Get-WinEvent -Path 'C:\Events\YARASigma\lab_events_4.evtx' |
where {($_.ID -eq "1006" -or $_.ID -eq "1116" -or $_.ID -eq "1015" -or $_.ID -eq "1117") } |
select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

The correction replaces **$*** with **$_**, the PowerShell pipeline variable representing the current event object. The filter retains the same four Event IDs as the original investigation.

### Results: 

| Field | Value |
|-------|-------|
| Event Source | Microsoft Defender |
| Event IDs | `1006`, `1015`, `1116`, `1117` |
| Malicious Driver | `mimidrv.sys` |

### Analysis: 

The translated PowerShell query filtered Windows Defender events associated with malware detection and remediation. Review of the event messages revealed that Microsoft Defender had identified the malicious driver mimidrv.sys.

The finding establishes that the driver was reported in the Defender event telemetry. It does not independently prove that the driver was loaded, executed, or used for credential theft.

## Investigation Findings 

Translation of the Sigma rule successfully produced a PowerShell query capable of identifying Windows Defender threat events within the supplied EVTX file.

Analysis of the matching events revealed Defender-reported threat activity, including a reference to`mimidrv.sys` as the malicious driver reported by Microsoft Defender. 

The investigation demonstrated how Sigma rules can be translated and applied using offline Windows event logs.

The primary confirmed finding is the presence of **mimidrv.sys** in the Defender detection messages. Additional endpoint telemetry would be needed to determine whether the driver was executed or associated with other attacker actions.

## Detection Logic

### Windows Defender Threat Events 

The translated Sigma rule filters Windows Defender events associated with malware detection and remediation by monitoring Event IDs **1006**, **1015**, **1116**, and **1117**. These events provide valuable telemetry describing detected threats, remediation actions, and malware-related activity, making them useful source of evidence during Defender investigations.

Event IDs identify categories of Defender telemetry; individual events must still be examined to determine the reported threat, affected artifact, and remediation status.

### Defender Detection Messages 

Windows Defender event messages contain detailed information describing detected threats, including the detection source, affected files, malware names, and remediation status. 

Reviewing these messages enables analysts to extract potential indicators of compromise and identify malicious files, drivers, or tools reported by Microsoft Defender.

### Malicious Driver Identification

Analysis of the translated Defender events identified the malicious driver `mimidrv.sys`. 

The driver name is associated with Mimikatz-related credential-access tooling. However, the Defender detection alone does not establish whether the driver was loaded or used to access credentials. Correlation with driver-load telemetry and other endpoint events would be necessary to confirm subsequent activity.

## Investigation Artifacts and Indicators

| IOC Type | Value |
|-----------|-------|
| Sigma Rule | `win_defender_threat.yml` |
| Event Log | `lab_events_4.evtx` |
| Translation Tool | `sigmac` |
| Output Query | PowerShell (`Get-WinEvent`) |
| Event IDs | `1006`, `1015`, `1116`, `1117` |
| Malicious Driver | `mimidrv.sys` |

**Note**: The Sigma rule, EVTX filename, translation tool, and Event IDs are investigation artifacts or telemetry references rather than IOCs. The Defender-reported driver name is the principal candidate indicator identified in this investigation.

## Lessons Learned

- **Sigma Rule Translation**: Sigma YAML detection logic can be converted into platform-specific queries using tools such as **sigmac**.

- **Offline EVTX Investigation**: **Get-WinEvent** enables analysis of exported Windows event logs without direct access to the original endpoint.

- **Windows Defender Telemetry**: Defender events can identify reported malicious files, drivers, and other threat artifacts.

- **Detection Validation**: Translated queries should be reviewed for syntax, field compatibility, and consistency with the original Sigma rule.

- **Investigation Finding**: The analyzed Defender event messages identified **mimidrv.sys** as the reported malicious driver.

## Conclusion

This investigation demonstrated how Sigma rules can be translated into executable PowerShell queries and applied against offline Windows event logs.

By combining Sigma detection engineering with Windows Defender telemetry,the analysis identified the malicious driver `mimidrv.sys` within the supplied Defender event records.

The investigation also highlighted the importance of validating platform-independent detection logic against recorded telemetry and reviewing translated queries before operational deployment.

Overall, the investigation demonstrates practical experience in Sigma rule translation, PowerShell event filtering, offline EVTX analysis, and interpretation of Microsoft Defender threat detections within a controlled training environment.
