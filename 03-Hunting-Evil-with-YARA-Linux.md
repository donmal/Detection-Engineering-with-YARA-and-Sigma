# 03 - Hunting Evil with YARA - Linux

## Executive Summary 

This investigation focused on detecting ransomware activity through memory-based YARA hunting using the Volatility Framework. By scanning a Windows memory image for ransomware-related artifacts, the investigation demonstrated how memory forensics can identify malicious processes, recover evidence of anti-recovery behavior, and attribute destructive actions to the responsible executable even when direct access to the compromised system is unavailable.

## Investigation Objectives 

- Perform memory-based malware hunting using Volatility and YARA.
- Identify ransomware artifacts within a Windows memory image.
- Detect commands associated with Windows Shadow Copy deletion.
- Attribute malicious activity to the responsible process.
- Understand ransomware anti-recovery techniques.
- Map observed behavior to MITRE ATT&CK.

## Challenge Context 

The investigation was initiated after a Windows system was suspected of being compromised by ransomware. Because direct access to the affected host was unavailable, analysts were provided with a memory dump and tasked with identifying evidence of malicious activity through memory forensics.

Using the Volatility Framework and the `yarascan` plugin, the investigation focused on locating ransomware-related artifacts, identifying commands associated with Windows Shadow Copy deletion, and determining which process was responsible for the observed anti-recovery behaviour.

## Background

### What is Memory-based YARA Hunting?

Memory-based YARA hunting applies YARA signatures directly to memory images or the memory of running processes rather than scanning files stored on disk. This technique enables analysts to identify malware that executes entirely in memory, injected code, unpacked payloads, and other runtime artifacts that may not be recoverable through traditional file-based analysis.

### Why Analyze Memory Dumps?

Memory dumps preserve the runtime state of a compromised system, including active processes, loaded modules, injected code, network connections, and sensitive data residing in memory. Memory forensics therefore provides valuable evidence even when malware has deleted itself or otherwise removed traces from disk.

### What is Volatility? 

Volatility is an open-source memory forensics framework used to analyze memory images from Windows, Linux, and macOS systems. It provides numerous plugins that allow investigators to enumerate processes, inspect memory regions, recover injected code, identify malware artifacts, and perform advanced forensic analysis.

### What is yarascan? 

The `yarascan` plugin integrates YARA scanning capabilities into the Volatility Framework. It allows investigators to search memory images for YARA rules or direct string patterns, making it particularly effective for identifying malware-specific artifacts, ransomware indicators, and injected payloads within process memory.

### Ransomware and Shadow Copy Deletion 

Many ransomware families attempt to prevent victims from recovering encrypted files by deleting Windows Volume Shadow Copies before or during encryption. Utilities such as `vssadmin` and `wmic shadowcopy` are frequently abused to remove recovery points, making these commands valuable indicators during ransomware investigations.

### Why Shadow Copy Deletion Matters?

Shadow Copy deletion represents a common anti-recovery technique used by ransomware operators to maximize the impact of encryption. Detecting evidence of these commands within memory or system logs provides strong contextual evidence of ransomware activity and helps investigators attribute destructive behavior to the responsible process.

## Investigation Exercise

### Objective: 

Analyze the provided Windows memory image using Volatility `yarascan` to identify the process responsible for deleting Windows Shadow Copies.

### Question: 

Use the Volatility `yarascan` plugin against the following memory image:

`/home/htb-student/MemoryDumps/compromised_system.raw`

Identify the process responsible for deleting Windows Shadow Copies.

**Answer format**

Process name.

### Solution:

`@WanaDecryptor@`

## Detection Engineering Concepts 

WannaCry/Wana Decrypt0r uses commands such as:

vssadmin delete shadows /all /quiet
wmic shadowcopy delete

These commands are used to delete Windows Volume Shadow Copies and prevent file recovery after encryption.

## Investigation Query #1 

### Purpose: 

Identify ransomware-related memory artifacts associated with Windows Shadow Copy deletion.

### Command:

vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -U "vssadmin"

### Results:

| Field | Value |
|-------|-------|
| Memory Image | `compromised_system.raw` |
| Search Pattern | `vssadmin` |
| Plugin | `yarascan` |
| Process Identified | `@WanaDecryptor@` |
| Malware Family | WannaCry / Wana Decrypt0r |

### Query Analysis:

The `yarascan` plugin searched the memory image for the string `vssadmin`, a well-known indicator associated with Windows Shadow Copy deletion. Analysis of the matching memory region attributed the artifact to the process `@WanaDecryptor@`, confirming that the ransomware was responsible for executing anti-recovery commands designed to prevent file restoration.

## Investigation Workflow 

The investigation followed a structured workflow:
1. Review common ransomware behaviors associated with Windows Shadow Copy deletion.
2. Identify reliable search patterns such as `vssadmin`, `wmic shadowcopy`, and `delete shadows`.
3. Execute the Volatility `yarascan` plugin against the memory image.
4. Review matching memory artifacts and identify the associated process.
5. Attribute the observed anti-recovery behavior to the responsible executable.
6. Validate the findings against known WannaCry ransomware characteristics.

## Detection Engineering Concepts

### Memory Hunting with YARA 

Memory-based YARA hunting enables analysts to identify malware artifacts that exist only during runtime. This technique is particularly valuable for detecting ransomware, injected shellcode, and fileless malware that may evade traditional file-based detection.

### Volatility yarascan

The `yarascan` plugin combines Volatility's memory forensics capabilities with YARA pattern matching, allowing investigators to search entire memory images for malware-specific strings, byte sequences, or complete YARA signatures.

### Direct String Matching

Searching for high-confidence strings such as `vssadmin` provides an effective starting point during memory hunting. Direct string matching enables investigators to quickly identify suspicious memory regions before performing more detailed malware analysis.

## Detection Logic 

### Shadow Copy Deletion

The command `vssadmin delete shadows` is widely used by ransomware families to delete Windows Volume Shadow Copies and prevent victims from restoring encrypted files. Detection of this command within memory provides a strong indicator of ransomware anti-recovery behavior.

### WMIC Shadow Deletion

The command `wmic shadowcopy delete` provides an alternative method for deleting Windows Shadow Copies. Malware frequently abuses this utility to achieve the same objective as `vssadmin`, making both commands valuable indicators during ransomware investigations.

### Memory Attribution

Identifying the process associated with a matched memory artifact significantly improves investigation confidence. In this case, attribution of the `vssadmin` artifact to the `@WanaDecryptor@` process directly linked the observed anti-recovery activity to the WannaCry ransomware family.

## IOC Summary

| IOC Type | Value |
|-----------|-------|
| Memory Image | `/home/htb-student/MemoryDumps/compromised_system.raw` |
| Detection Tool | Volatility |
| Plugin | `yarascan` |
| Search Pattern | `vssadmin` |
| Process | `@WanaDecryptor@` |
| Malware Family | WannaCry / Wana Decrypt0r |

## Data Sources 

| Source | Purpose |
|---------|----------|
| Windows Memory Dump | Memory forensic analysis |
| Volatility Framework | Memory analysis |
| `yarascan` Plugin | YARA-based memory hunting |
| YARA Pattern Matching | Malware artifact detection |
| Memory-resident Process Artifacts | Process attribution | 

## Investigation Scope

The investigation focused on identifying ransomware artifacts within a Windows memory image using Volatility and YARA. Particular emphasis was placed on detecting evidence of Windows Shadow Copy deletion, attributing the observed behavior to the responsible process, and understanding ransomware anti-recovery techniques through memory forensics.

## Investigation Methodology 

The investigation followed a structured methodology:

1. Review common ransomware anti-recovery techniques.
2. Select appropriate search patterns for memory hunting.
3. Scan the memory image using Volatility `yarascan`.
4. Review matching memory artifacts.
5. Attribute artifacts to running processes.
6. Validate findings against known ransomware behaviors.

## Investigation Overview 

The investigation combined memory forensics with YARA-based artifact hunting to identify ransomware activity within a compromised Windows memory image. By searching for Shadow Copy deletion commands commonly associated with WannaCry, analysts successfully attributed anti-recovery behavior to the responsible process and demonstrated how memory-resident artifacts can provide valuable evidence even when direct access to the original host is unavailable.

## Investigation Findings 

Memory analysis identified the string `vssadmin` within the compromised memory image, indicating execution of a Windows Shadow Copy deletion command commonly associated with ransomware. Correlation of the matching artifact with process ownership attributed the activity to the `@WanaDecryptor@` process, confirming behavior consistent with the WannaCry ransomware family and its use of anti-recovery techniques prior to or during file encryption.

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Impact | Data Encrypted for Impact | T1486 | Ransomware encryption activity |
| Impact | Inhibit System Recovery | T1490 | Deletion of Windows Volume Shadow Copies |
| Defense Evasion | Indicator Removal on Host | T1070 | Removal of recovery artifacts |
| Discovery | File and Directory Discovery | T1083 | Enumeration commonly preceding encryption |

## Placeholder Screenshots

Figure 1 - VMware article showing Wana Decrypt0r shadow deletion behavior
Figure 2 - vssadmin and wmic shadowcopy command reference
Figure 3 - Volatility yarascan output showing @WanaDecryptor@

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Memory Forensics | Memory dumps can reveal ransomware artifacts and malicious commands even when direct access to the compromised host is unavailable. |
| Anti-recovery Techniques | Ransomware commonly deletes Windows Volume Shadow Copies to prevent victims from restoring encrypted files. |
| Memory Hunting | The Volatility `yarascan` plugin provides an effective method for searching memory images for specific strings and malware-related artifacts. |
| Shadow Copy Indicators | The string `vssadmin` is a high-confidence indicator of Windows Shadow Copy deletion activity and is frequently associated with ransomware behavior. |
| Process Attribution | Correlating matched memory artifacts with process ownership enables investigators to attribute malicious activity to the responsible executable. In this investigation, the process `@WanaDecryptor@` was identified as responsible for the observed shadow copy deletion behavior. |

## Conclusion

This investigation demonstrated how memory forensics and YARA-based hunting can be combined to detect ransomware activity when direct access to a compromised system is unavailable. By identifying memory-resident artifacts associated with Windows Shadow Copy deletion and attributing them to the `@WanaDecryptor@` process, the investigation highlighted the value of Volatility `yarascan` in supporting ransomware investigations, process attribution, and incident response through memory-based evidence.
