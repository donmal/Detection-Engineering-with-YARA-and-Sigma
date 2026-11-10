# 06 - Hunting Evil with Sigma - Splunk

## Executive Summary

This investigation focused on translating Sigma detection rules into Splunk Search Processing Language (SPL) and validating the resulting detection logic against Windows telemetry ingested into Splunk. 

Through Sigma rule translation, Splunk hunting, and file creation event analysis, the investigation demonstrated how platform-independent detection logic can be operationalized within a SIEM to identify suspicious archive creation associated that may warrant further investigation for reconnaissance or post-exploitation activity.

The investigation identified the archive **20221108112718_BloodHound.zip** through the **TargetFilename** field of a matching Windows file creation event. The filename suggests a possible association with BloodHound-related Active Directory analysis, although the archive contents and its intended use were not independently verified.

## Investigation Objectives 

- Understand how Sigma rules are translated into Splunk SPL.
- Generate Splunk detection logic using `sigmac`.
- Execute Sigma-derived SPL searches within Splunk.
- Identify suspicious archive creation events.
- Analyze the `TargetFilename` field to identify dropped files.
- Map observed behavior to MITRE ATT&CK where supported by the investigation evidence..

## Investigation Context 

This investigation was conducted in a controlled Hack The Box Academy environment using a provided Sigma rule and Windows file creation telemetry available in Splunk. The objective was to translate the Sigma rule into SPL, execute the resulting search, and identify archive files recorded in matching events.

Using `sigmac`, Splunk Search & Reporting, and Windows file creation telemetry, the investigation focused on identifying archive files created by applications covered by the Sigma detection logic and extracting the corresponding `TargetFilename` for further analysis.

## Background 

### What is Sigma? 

Sigma is an open, platform-independent rule format that describes log-based detections using standardized YAML syntax. Once translated into platform-specific queries, Sigma rules can be executed across SIEM platforms such as Splunk, Elastic, Sentinel, and QRadar subject to the capabilities and field mappings of each platform.

### Sigma-to-Splunk Translation 

The `sigmac` utility converts Sigma rules into Splunk Search Processing Language (SPL), allowing analysts to execute standardized detections directly within Splunk. 

This approach reduces manual query development while supporting consistency between detection engineering and operational threat hunting.

The investigation uses the legacy **sigmac** utility and a Splunk configuration file to translate the rule into the target query format.

### Splunk Hunting 

Splunk enables analysts to search, correlate, and investigate Windows telemetry using SPL. By combining Sigma-generated queries with indexed event data, investigators can rapidly evaluate detections, identify potentially suspicious artifacts, and perform large-scale threat hunting.

### Suspicious Archive Creation 

Attackers frequently create compressed archive files to package malware, offensive tools, reconnaissance data, or stolen information before transferring or exfiltrating it. 

Monitoring archive creation by unexpected applications provides valuable visibility into staging and post-exploitation activity.

However, archive creation is also common during legitimate administrative and user activity. The originating process, file contents, and surrounding events are necessary to assess whether an archive is suspicious.

### TargetFilename Analysis

The `TargetFilename` field records the full path of newly created files within supported Windows file creation events. 

During threat hunting, this field enables analysts to identify suspicious files, determine where they were written, and correlate file creation activity with the responsible process.

## Data Sources 

| Source | Purpose |
|---------|----------|
| Windows File Creation Events | File creation telemetry |
| Splunk Index | Centralized event analysis |
| Sigma Rule | Detection logic |
| Splunk SPL | Threat hunting |
| sigmac | Sigma rule translation |

## Investigation Scope 

The investigation focused on translating a Sigma rule into Splunk SPL and validating the generated detection logic against Windows file creation events stored within Splunk.

Particular emphasis was placed on identifying archive files created by processes covered by the Sigma rule and extracting the corresponding `TargetFilename` for further analysis.

## Investigation Methodology 

The investigation followed a structured methodology:

1. Review the Sigma detection rule.
2. Translate the rule into Splunk SPL using `sigmac`.
3. Execute the generated SPL search.
4. Review matching file creation events.
5. Identify the created archive.
6. Interpret the matching event and document the limits of the available evidence.

## Investigation Overview 

The investigation combined Sigma rule translation with Splunk-based threat hunting to apply standardized detection logic against Windows telemetry. 

By executing a Sigma-derived SPL query, analysts identified archive creation activity and extracted the archive path recorded within the `TargetFilename` field.

The identified archive was named **20221108112718_BloodHound.zip**. Its name provided a lead for further investigation into potential Active Directory reconnaissance artifacts.

## Sigma-to-Splunk Detection Investigation  

**Analysis Objective**: Translate the provided Sigma rule into Splunk SPL and investigate matching Windows file creation events to identify archive artifacts.

**Sigma Rule**:

'C:\Rules\sigma\file_event_win_app_dropping_archive.yml'

## 1. Sigma Rule Translation into Splunk SPL

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

### Analysis

The sigmac utility translated the Sigma rule into Splunk Search Processing Language (SPL), producing a query capable of identifying archive files created by processes specified in the rule within indexed Windows telemetry.

The generated SPL should be reviewed for field compatibility, wildcard behavior, and consistency with the original Sigma rule before being used as a production detection.

## 2. Splunk Archive Creation Hunting

### Purpose

Execute the translated Splunk query and identify the created archive.

### Command

((Image="*\\winword.exe" OR Image="*\\excel.exe" OR Image="*\\powerpnt.exe" OR Image="*\\msaccess.exe" OR Image="*\\mspub.exe" OR Image="*\\eqnedt32.exe" OR Image="*\\visio.exe" OR Image="*\\wordpad.exe" OR Image="*\\wordview.exe" OR Image="*\\certutil.exe" OR Image="*\\certoc.exe" OR Image="*\\CertReq.exe" OR Image="*\\Desktopimgdownldr.exe" OR Image="*\\esentutl.exe" OR Image="*\\finger.exe" OR Image="*\\notepad.exe" OR Image="*\\AcroRd32.exe" OR Image="*\\RdrCEF.exe" OR Image="*\\mshta.exe" OR Image="*\\hh.exe" OR Image="*\\sharphound.exe") (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z" OR TargetFilename="*.diagcab" OR TargetFilename="*.appx"))

**Query interpretation**: The search combines two conditions: a process image matching one of the listed executables and a **TargetFilename** ending in one of the specified archive-related extensions.

The query does not independently establish that the process or archive is malicious. It identifies events matching the selected hunting criteria.

### Results 

| Field | Value |
|-------|-------|
| Platform | Splunk |
| Field of Interest | `TargetFilename` |
| Archive File | `C:\Users\waldo\Downloads\20221108112718_BloodHound.zip` |

### Analysis 

The generated SPL searched Windows file creation events for archive files created by applications commonly abused during attacker activity. 

Analysis of the returned event identified the archive **20221108112718_BloodHound.zip**, whose filename suggests a possible relationship to BloodHound-related Active Directory analysis.

The available results do not specify the matching process image, the archive contents, or whether BloodHound collection activity occurred. These details would be necessary to establish the event's role in a larger attack sequence.

## Investigation Findings

Translation of the Sigma rule successfully produced a Splunk SPL query capable of identifying archive creation activity. 

Analysis of the returned event identified the archive `C:\Users\waldo\Downloads\20221108112718_BloodHound.zip`, demonstrating how Sigma-based detections can be operationalized within Splunk to detect file creation events that may be relevant to reconnaissance or post-exploitation investigations.

The confirmed finding is the archive path recorded in **TargetFilename**. The relationship to BloodHound tooling, the source process, and any subsequent data staging or exfiltration remain unverified from the documented results.


## Detection Logic 

### Suspicious Archive Creation 

Applications such as `notepad.exe`, `winword.exe`, `excel.exe`, `certutil.exe`, `mshta.exe`, and `SharpHound.exe` are included among the process images monitored by the Sigma-derived search.

Archive creation by these processes therefore represents a potentially useful hunting signal that requires additional context before being classified as malicious.

### Archive File Extensions 

The Sigma rule monitors archive extensions including `.zip`, `.rar`, `.7z`, `.diagcab`, and `.appx`. 

These file types can represent compressed archives or application package formats. Their presence alone does not establish data collection, staging, or exfiltration.

### TargetFilename Identification 

The investigation identified the archive `C:\Users\waldo\Downloads\20221108112718_BloodHound.zip` through the `TargetFilename` field.

Because BloodHound is widely used for Active Directory reconnaissance and attack-path analysis, the archive filename provides a relevant investigative lead for possible Active Directory reconnaissance activity.

However, the file's contents and origin were not examined in the documented investigation. A filename alone is insufficient to confirm that the archive contains BloodHound collection data or that malicious reconnaissance occurred.

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Sigma Translation | Sigma rules can be translated into Splunk SPL using `sigmac`, enabling standardized detections within Splunk. |
| Detection Validation | Generated SPL should always be reviewed and validated before deployment to ensure accurate detection results. |
| Archive Monitoring | Archive creation by unexpected applications provides a valuable hunting signal for staging and post-exploitation activity. |
| TargetFilename Analysis | The `TargetFilename` field enables investigators to identify the exact file created during suspicious activity. |
| Sigma Configuration | Configuration and mapping files significantly influence the generated SPL by translating Sigma fields into Splunk-compatible syntax. |

## Investigation Artifacts and Candidate Indicators

| IOC Type | Value |
|-----------|-------|
| Sigma Rule | `file_event_win_app_dropping_archive.yml` |
| Translation Tool | `sigmac` |
| Platform | Splunk |
| Field of Interest | `TargetFilename` |
| Target File | `C:\Users\waldo\Downloads\20221108112718_BloodHound.zip` |

**Note**: The Sigma rule, translation tool, platform, and field name are investigation metadata rather than IOCs. The archive path is the main artifact identified in the event data and should be treated as a candidate indicator pending further investigation.

## Conclusion

This investigation demonstrated how Sigma rules can be translated into Splunk Search Processing Language and applied against Windows telemetry within Splunk.

By combining Sigma detection engineering with Splunk threat hunting, analysts successfully identified the archive `C:\Users\waldo\Downloads\20221108112718_BloodHound.zip`, illustrating how standardized detection logic can revealfile creation artifacts that warrant further investigation for potential reconnaissance or post-exploitation activity.

The investigation demonstrates practical experience in Sigma-to-SPL translation, SIEM-based hunting, and Windows file creation event analysis. Additional evidence would be required to determine whether the identified archive was associated with malicious BloodHound activity or data staging.
