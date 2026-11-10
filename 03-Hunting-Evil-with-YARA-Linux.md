# 03 - Hunting Evil with YARA - Linux

## Executive Summary 

This investigation focused on detecting ransomware activity through memory-based YARA hunting using the Volatility Framework. By scanning a Windows memory image for ransomware-related artifacts, the investigation demonstrated how memory forensics can identify ransomware-associated process artifacts and indicators potentially related to anti-recovery activity even when direct access to the compromised system is unavailable.

The analysis searched for the string **vssadmin** within **compromised_system.raw** and identified an associated process named **@WanaDecryptor@**. This finding is consistent with WannaCry-related activity, although the documented evidence does not independently establish that a Shadow Copy deletion command was executed successfully.

## Investigation Objectives 

- Perform memory-based malware hunting using Volatility and YARA.
- Identify ransomware artifacts within a Windows memory image.
- Detect memory artifacts potentially associated with Windows Shadow Copy deletion.
- Identify the process associated with the matched memory artifact.
- Understand ransomware anti-recovery techniques.
- Map observed behavior to MITRE ATT&CK where supported by the available evidence.

## Investigation Context 

This investigation was conducted in a controlled Hack The Box Academy environment using a provided Windows memory image. The analysis was performed from a Linux-based investigation environment using Volatility to search for ransomware-related artifacts without interacting directly with the original Windows host.

Using the Volatility Framework and the `yarascan` plugin, the investigation focused on locating ransomware-related artifacts, identifying indicators potentially associated with Windows Shadow Copy deletion, and determining which process was associated with the identified memory artifact.

## Background

### What is Memory-based YARA Hunting?

Memory-based YARA hunting applies YARA signatures directly to memory images or the memory of running processes rather than scanning files stored on disk. This technique enables analysts to identify malware that executes entirely in memory, injected code, unpacked payloads, and other runtime artifacts that may not be recoverable through traditional file-based analysis.

### Why Analyze Memory Dumps?

Memory dumps preserve a snapshot of the runtime state of a compromised system, including active processes, loaded modules, injected code, network connections, and sensitive data residing in memory. Memory forensics therefore provides valuable evidence even when malware has deleted itself or otherwise removed traces from disk.

### What is Volatility? 

Volatility is an open-source memory forensics framework used to analyze memory images from Windows, Linux, and macOS systems. It provides numerous plugins that allow investigators to enumerate processes, inspect memory regions, recover injected code, identify malware artifacts, and perform advanced forensic analysis.

### What is yarascan? 

The `yarascan` plugin integrates YARA scanning capabilities into the Volatility Framework. It allows investigators to search memory images for YARA rules or direct string patterns, making it particularly effective for identifying malware-specific artifacts, ransomware indicators, and injected payloads within process memory.

### Ransomware and Shadow Copy Deletion 

Many ransomware families attempt to prevent victims from recovering encrypted files by deleting Windows Volume Shadow Copies before or during encryption. Utilities such as `vssadmin` and `wmic shadowcopy` are frequently abused to remove recovery points, making these commands valuable indicators during ransomware investigations.

### Why Shadow Copy Deletion Matters?

Shadow Copy deletion represents a common anti-recovery technique used by ransomware operators to maximize the impact of encryption. Detecting evidence of these commands within memory or system logs provides potential indicators of anti-recovery behavior that can guide further forensic investigation.

## Memory Forensic Investigation

**Investigation Objective**: Examine the provided Windows memory image for ransomware-associated artifacts using Volatility **yarascan**, focusing on references to **vssadmin** and identifying the process associated with the matching memory region.

**Memory Image**:

'/home/htb-student/MemoryDumps/compromised_system.raw'

## 1. Memory Artifact Hunting with Volatility 

### Purpose: 

Identify ransomware-related memory artifacts that may indicate Windows Shadow Copy deletion activity.

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

### Figure 5 - Volatility YARA Memory Scan 



### Analysis:

The `yarascan` plugin searched the memory image for the string `vssadmin`, a Windows utility that can be used to manage or delete Volume Shadow Copies. 

Analysis of the matching memory region identified an association with the process `@WanaDecryptor@`, providing a finding consistent with WannaCry-related activity and potential anti-recovery behavior.

The presence of **vssadmin** in process-associated memory does not, by itself, prove that a deletion command was executed. Confirming execution would require additional evidence, such as process creation logs, command-line artifacts, or other corroborating forensic records.

## Detection Logic 

### Shadow Copy Deletion

The command `vssadmin delete shadows` is widely used by ransomware families to delete Windows Volume Shadow Copies and prevent victims from restoring encrypted files.

The documented memory scan identified the string **vssadmin**, rather than the complete deletion command. Additional command-line context would be necessary to determine whether the artifact represented malicious Shadow Copy deletion activity.

### WMIC Shadow Deletion

The command `wmic shadowcopy delete` provides an alternative method for deleting Windows Shadow Copies. Malware frequently abuses this utility to achieve the same objective as `vssadmin`, making both commands valuable indicators during ransomware investigations.

This command is included as relevant detection context; the provided investigation does not document a matching **wmic shadowcopy** delete artifact.

### Memory Attribution

Identifying the process associated with a matched memory artifact significantly improves investigation confidence.

In this case, the **vssadmin** artifact was associated with the process name **@WanaDecryptor@**, supporting a WannaCry-related interpretation without independently proving execution of a Shadow Copy deletion command.

## Investigation Artifacts and Indicators

| IOC Type | Value |
|-----------|-------|
| Memory Image | `/home/htb-student/MemoryDumps/compromised_system.raw` |
| Detection Tool | Volatility |
| Plugin | `yarascan` |
| Search Pattern | `vssadmin` |
| Process | `@WanaDecryptor@` |
| Malware Family | WannaCry / Wana Decrypt0r |

**Note**: The memory image path, forensic tool, and plugin are investigation artifacts rather than IOCs. The **vssadmin** string is a contextual hunting indicator and is not inherently malicious. The process name is more distinctive, but its relationship to WannaCry should be corroborated with additional forensic evidence where available.

## Data Sources 

| Source | Purpose |
|---------|----------|
| Windows Memory Dump | Memory forensic analysis |
| Volatility Framework | Memory analysis |
| `yarascan` Plugin | YARA-based memory hunting |
| YARA Pattern Matching | Malware artifact detection |
| Memory-resident Process Artifacts | Process attribution | 

## Investigation Scope

The investigation focused on identifying ransomware artifacts within a Windows memory image using Volatility and YARA. Particular emphasis was placed on detecting memory references potentially associated with Windows Shadow Copy deletion and identifying the process associated with the matching artifact, and understanding ransomware anti-recovery techniques through memory forensics.

## Investigation Methodology 

The investigation followed a structured methodology:

1. Review common ransomware anti-recovery techniques.
2. Select appropriate search patterns for memory hunting.
3. Scan the memory image using Volatility `yarascan`.
4. Review matching memory artifacts.
5. Identify the process associated with the matched artifact.
6. Compare findings with known ransomware behavior and document evidentiary limitations.

## Investigation Overview 

The investigation combined memory forensics with YARA-based artifact hunting to identify ransomware activity within a compromised Windows memory image.

By searching for the **vssadmin** string, which may be associated with Shadow Copy deletion, the analysis identified an associated process named **@WannaDecryptor@** and demonstrated how memory-resident artifacts can provide valuable evidence even when direct access to the original host is unavailable.

## Investigation Findings 

Memory analysis identified the string `vssadmin` within the compromised memory image, providing a potential indicator of Shadow Copy-related activity.

Correlation of the matching artifact with process ownership associated the finding with the `@WanaDecryptor@` process, supporting an interpretation consistent with WannaCry-related activity.

The available findings do not establish whether the full Shadow Copy deletion command was executed or whether recovery points were actually removed.

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Impact | Inhibit System Recovery | T1490 | Potential anti-recovery behavior associated with the **vssadmin** artifact; command execution not independently confirmed |

**Mapping assessment**: T1490 is relevant to the investigation's hypothesis because it covers techniques used to inhibit system recovery, including Shadow Copy deletion. However, the available evidence supports only a potential mapping, not confirmed execution of the technique. T1486, T1070, and T1083 should be removed because the provided analysis does not demonstrate those behaviors.

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| Memory Forensics | Memory dumps can reveal ransomware artifacts and malicious commands even when direct access to the compromised host is unavailable. |
| Anti-recovery Techniques | Ransomware commonly deletes Windows Volume Shadow Copies to prevent victims from restoring encrypted files. |
| Memory Hunting | The Volatility `yarascan` plugin provides an effective method for searching memory images for specific strings and malware-related artifacts. |
| Shadow Copy Indicators | The string vssadmin is a useful hunting lead, but it requires command-line context and supporting evidence to distinguish legitimate administrative activity from malicious Shadow Copy deletion. |
| Process Attribution | Associating a matched memory artifact with a process provides valuable investigative context. The identified @WanaDecryptor@ process supports a ransomware-related finding, although execution of the suspected deletion command remains unverified. |

## Conclusion

This investigation demonstrated how memory forensics and YARA-based hunting can be combined to detect ransomware-associated artifacts when direct access to a compromised system is unavailable.

By identifying memory-resident artifacts containing the **vssadmin** string and associating the finding with the **@WanaDecryptor@** process, the investigation highlighted the value of Volatility `yarascan` in supporting ransomware investigations, process-level artifact analysis, and incident response through memory-based evidence.

The findings are consistent with possible WannaCry-related anti-recovery activity, but additional forensic evidence would be required to confirm command execution and successful Shadow Copy deletion.
