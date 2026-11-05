# 06 - Hunting Evil with Sigma - Splunk

## Executive Summary

This investigation focused on translating Sigma detection rules into Splunk Search Processing Language (SPL) and validating the resulting detection logic against Windows telemetry ingested into Splunk. Through Sigma rule translation, Splunk hunting, and file creation event analysis, the investigation demonstrated how platform-independent detection logic can be operationalized within a SIEM to identify suspicious archive creation associated with attacker tooling and post-exploitation activity.

## Investigation Objectives 

- Understand how Sigma rules are translated into Splunk SPL.
- Generate Splunk detection logic using `sigmac`.
- Execute Sigma-derived SPL searches within Splunk.
- Identify suspicious archive creation events.
- Analyze the `TargetFilename` field to identify dropped files.
- Map observed behavior to MITRE ATT&CK.

## Challenge Context 

The investigation was initiated after security analysts identified potentially suspicious archive creation activity within Windows telemetry collected by Splunk. Because attackers frequently package tools, stolen data, or reconnaissance results into compressed archives, analysts were tasked with translating an existing Sigma rule into Splunk SPL and validating the resulting detection against ingested event data.
Using `sigmac`, Splunk Search & Reporting, and Windows file creation telemetry, the investigation focused on identifying archive files created by suspicious applications and extracting the corresponding `TargetFilename` for further analysis.

## Background 

### What is Sigma? 

Sigma is an open, platform-independent rule format that describes log-based detections using standardized YAML syntax. Once translated into platform-specific queries, Sigma rules can be executed across SIEM platforms such as Splunk, Elastic, Sentinel, and QRadar while maintaining consistent detection logic.

### Sigma-to-Splunk Translation 

The `sigmac` utility converts Sigma rules into Splunk Search Processing Language (SPL), allowing analysts to execute standardized detections directly within Splunk. This approach reduces manual query development while ensuring consistency between detection engineering and operational threat hunting.

### Splunk Hunting 

Splunk enables analysts to search, correlate, and investigate Windows telemetry using SPL. By combining Sigma-generated queries with indexed event data, investigators can rapidly validate detections, identify malicious artifacts, and perform large-scale threat hunting.

### Suspicious Archive Creation 

Attackers frequently create compressed archive files to package malware, offensive tools, reconnaissance data, or stolen information before transferring or exfiltrating it. Monitoring archive creation by unexpected applications provides valuable visibility into staging and post-exploitation activity.

### TargetFilename Analysis

The `TargetFilename` field records the full path of newly created files within Windows file creation events. During threat hunting, this field enables analysts to identify suspicious files, determine where they were written, and correlate file creation activity with the responsible process.

## MITRE ATT&CK Mapping (Background) 

| Technique | ATT&CK ID |
|-----------|-----------|
| PowerShell | T1059.001 |
| Archive Collected Data | T1560.001 |
| Data Staged | T1074 |

## Data Sources 

| Source | Purpose |
|---------|----------|
| Windows File Creation Events | File creation telemetry |
| Splunk Index | Centralized event analysis |
| Sigma Rule | Detection logic |
| Splunk SPL | Threat hunting |
| sigmac | Sigma rule translation |

## Investigation Scope 

The investigation focused on translating a Sigma rule into Splunk SPL and validating the generated detection logic against Windows file creation events stored within Splunk. Particular emphasis was placed on identifying archive files created by suspicious applications and extracting the corresponding `TargetFilename` for further analysis.

## Investigation Methodology 

The investigation followed a structured methodology:

1. Review the Sigma detection rule.
2. Translate the rule into Splunk SPL using `sigmac`.
3. Execute the generated SPL search.
4. Review matching file creation events.
5. Identify the created archive.
6. Validate the Sigma detection.

## Investigation Overview 

The investigation combined Sigma rule translation with Splunk-based threat hunting to validate standardized detection logic against Windows telemetry. By executing a Sigma-derived SPL query, analysts identified suspicious archive creation activity and extracted the archive path recorded within the `TargetFilename` field.

## Investigation Exercise 

### Objective 

Translate the provided Sigma rule into Splunk SPL and identify the archive file returned by the generated search.

### Question 

Translate the Sigma rule:

`file_event_win_app_dropping_archive.yml`

into Splunk SPL using `sigmac`.

Execute the generated search within Splunk Search & Reporting and identify the returned `TargetFilename`.

**Answer format**

Full file path.

### Solution

`C:\Users\waldo\Downloads\20221108112718_BloodHound.zip`

## Investigation Query #1

### Purpose 

Translate the Sigma rule into Splunk SPL.

### Command

cd C:\Tools\sigma-0.21\tools

python sigmac -t splunk C:\Rules\sigma\file_event_win_app_dropping_archive.yml --config .\config\splunk-windows.yml

### Results 

| Field | Value |
|-------|-------|
| Input Rule | `file_event_win_app_dropping_archive.yml` |
| Translation Tool | `sigmac` |
| Output Format | Splunk SPL |

### Query Analysis

The sigmac utility translated the Sigma rule into Splunk Search Processing Language (SPL), producing a query capable of identifying archive files created by suspicious applications within indexed Windows telemetry.

## Investigation Query #2 

### Purpose

Execute the translated Splunk query and identify the created archive.

### Command

((Image="*\\winword.exe" OR Image="*\\excel.exe" OR Image="*\\powerpnt.exe" OR Image="*\\msaccess.exe" OR Image="*\\mspub.exe" OR Image="*\\eqnedt32.exe" OR Image="*\\visio.exe" OR Image="*\\wordpad.exe" OR Image="*\\wordview.exe" OR Image="*\\certutil.exe" OR Image="*\\certoc.exe" OR Image="*\\CertReq.exe" OR Image="*\\Desktopimgdownldr.exe" OR Image="*\\esentutl.exe" OR Image="*\\finger.exe" OR Image="*\\notepad.exe" OR Image="*\\AcroRd32.exe" OR Image="*\\RdrCEF.exe" OR Image="*\\mshta.exe" OR Image="*\\hh.exe" OR Image="*\\sharphound.exe") (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z" OR TargetFilename="*.diagcab" OR TargetFilename="*.appx"))

### Results 

| Field | Value |
|-------|-------|
| Platform | Splunk |
| Field of Interest | `TargetFilename` |
| Archive File | `C:\Users\waldo\Downloads\20221108112718_BloodHound.zip` |

### Query Analysis 

The generated SPL searched Windows file creation events for archive files created by applications commonly abused during attacker activity. Analysis of the returned event identified the archive BloodHound.zip, indicating the creation of a compressed file commonly associated with Active Directory reconnaissance.

## Investigation Findings

Translation of the Sigma rule successfully produced a Splunk SPL query capable of identifying suspicious archive creation activity. Analysis of the returned event identified the archive `C:\Users\waldo\Downloads\20221108112718_BloodHound.zip`, demonstrating how Sigma-based detections can be operationalized within Splunk to detect attacker tooling, reconnaissance artifacts, and post-exploitation staging activity.

## Investigation Workflow 

The investigation followed a structured workflow:

1. Review the Sigma rule `file_event_win_app_dropping_archive.yml`.
2. Translate the rule into Splunk SPL:
```bash
python sigmac -t splunk C:\Rules\sigma\file_event_win_app_dropping_archive.yml --config .\config\splunk-windows.yml
```
3. Execute the generated SPL search within Splunk Search & Reporting.
4. Review matching Windows file creation events.
5. Extract the value of the `TargetFilename` field.
6. Validate that the identified archive corresponds to suspicious post-exploitation activity.

## Detection Engineering Concepts 

### Sigma-to-Splunk Translation

Sigma rules can be translated directly into Splunk Search Processing Language (SPL) using `sigmac`, enabling standardized detection logic to be executed within Splunk. This translation reduces manual query development while ensuring consistency between detection engineering and operational threat hunting.

### Splunk Threat Hunting

Splunk provides centralized search and correlation capabilities for Windows telemetry, allowing analysts to execute Sigma-derived SPL searches against large datasets and rapidly identify suspicious activity through indexed event data.

### Archive Creation Monitoring

Monitoring archive creation events helps identify attacker staging activity, offensive tooling, and data preparation prior to exfiltration. Archive files created by unexpected applications frequently represent valuable hunting opportunities during post-exploitation investigations.

### TargetFilename Analysis

The `TargetFilename` field records the complete path of newly created files and provides investigators with direct visibility into file creation activity. Reviewing this field enables analysts to identify suspicious artifacts, determine their storage location, and correlate file creation with the originating process.

## Detection Logic 

### Suspicious Archive Creation 

Applications such as `notepad.exe`, `winword.exe`, `excel.exe`, `certutil.exe`, `mshta.exe`, and `SharpHound.exe` do not typically create compressed archives during normal operation. Archive creation by these processes therefore represents a valuable indicator of staging or post-exploitation activity.

### Archive File Extensions 

The Sigma rule monitors archive extensions including `.zip`, `.rar`, `.7z`, `.diagcab`, and `.appx`. These file types are commonly used to package offensive tools, reconnaissance data, or stolen information prior to transfer or exfiltration.

### TargetFilename Identification 

The investigation identified the archive `C:\Users\waldo\Downloads\20221108112718_BloodHound.zip` through the `TargetFilename` field. Because BloodHound is widely used for Active Directory reconnaissance and attack-path analysis, the observed archive represents a high-confidence indicator of post-exploitation activity and potential domain reconnaissance.

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Collection | Archive Collected Data | T1560.001 | Creation of compressed archives |
| Collection | Data Staged | T1074 | Packaging data before exfiltration |
| Discovery | Permission Groups Discovery | T1069 | BloodHound reconnaissance |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Sigma rule translation and hunting workflows |

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Sigma Translation | Sigma rules can be translated into Splunk SPL using `sigmac`, enabling standardized detections within Splunk. |
| Detection Validation | Generated SPL should always be reviewed and validated before deployment to ensure accurate detection results. |
| Archive Monitoring | Archive creation by unexpected applications provides a valuable hunting signal for staging and post-exploitation activity. |
| TargetFilename Analysis | The `TargetFilename` field enables investigators to identify the exact file created during suspicious activity. |
| Sigma Configuration | Configuration and mapping files significantly influence the generated SPL by translating Sigma fields into Splunk-compatible syntax. |

## IOC Summary

| IOC Type | Value |
|-----------|-------|
| Sigma Rule | `file_event_win_app_dropping_archive.yml` |
| Translation Tool | `sigmac` |
| Platform | Splunk |
| Field of Interest | `TargetFilename` |
| Target File | `C:\Users\waldo\Downloads\20221108112718_BloodHound.zip` |

## Placeholder Screenshots

Figure 1 - Splunk LSASS MiniDump comsvcs.dll detection
Figure 2 - Splunk notepad spawning suspicious child process
Figure 3 - sigmac translating Sigma rule to Splunk SPL

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Sigma Translation | Sigma rules can be translated into Splunk SPL using `sigmac`, enabling standardized detections within Splunk. |
| Detection Validation | Generated SPL should always be reviewed and validated before deployment to ensure accurate detection results. |
| Archive Monitoring | Archive creation by unexpected applications provides a valuable hunting signal for staging and post-exploitation activity. |
| TargetFilename Analysis | The `TargetFilename` field enables investigators to identify the exact file created during suspicious activity. |
| Sigma Configuration | Configuration and mapping files significantly influence the generated SPL by translating Sigma fields into Splunk-compatible syntax. |

## Conclusion

This investigation demonstrated how Sigma rules can be translated into Splunk Search Processing Language and validated against Windows telemetry within Splunk. By combining Sigma detection engineering with Splunk threat hunting, analysts successfully identified the suspicious archive `C:\Users\waldo\Downloads\20221108112718_BloodHound.zip`, illustrating how standardized detection logic can reveal attacker tooling, reconnaissance artifacts, and post-exploitation staging activity within enterprise environments.
