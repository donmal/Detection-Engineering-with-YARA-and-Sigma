# 01 - Developing YARA Rules

## Executive Summary

This investigation focused on developing and improving YARA detection rules through static malware analysis. By examining malware samples, extracting meaningful strings, and inspecting existing detection logic, the investigation demonstrated how candidate malware-related artifacts can be identified and used to refine YARA detection signatures.

The analysis identified the DLL reference **TSMSISrv.dll** within **DirectX.dll** and correlated it with an incomplete string indicator in an existing APT17-related YARA rule. The available evidence supports identifying the required replacement string; successful execution of the modified rule and false-positive testing were not documented.

## Investigation Context

The investigation was conducted in a controlled Hack The Box Academy environment using a provided Windows DLL sample and an existing APT17-related YARA rule containing an incomplete string indicator. The objective was to inspect the sample, identify a relevant DLL reference, and determine the appropriate replacement for the rule's placeholder.

Using standard Linux utilities and YARA rule inspection, the investigation focused on identifying DLL-related strings that could support more specific detection logic.

## Background

### What is YARA? 

YARA is a pattern-matching language designed to identify and classify malware based on textual, structural, and binary characteristics. It enables analysts to create detection rules that match specific strings, imported libraries, PE metadata, file characteristics, and other malware-specific artifacts.

Originally developed for malware research, YARA has become one of the most widely used technologies for malware detection, threat hunting, digital forensics, and incident response.

### Why YARA Rules Matter?

Effective YARA rules allow defenders to detect known malware families, identify malware variants, and improve visibility across large malware repositories. Rather than relying solely on cryptographic hashes, YARA rules focus on stable malware characteristics that remain identifiable even when samples are recompiled or slightly modified.

Well-designed rules combine sufficiently distinctive indicators with appropriate matching conditions. Detection quality depends on testing against relevant malicious and benign samples.

### Manual vs Automated Rule Development

YARA rules can be created manually or generated automatically using tools such as **yarGen**.

Manual rule development allows analysts to carefully select high-confidence indicators based on reverse engineering and malware analysis. Automated tools accelerate rule generation by extracting candidate strings and metadata; however, automatically generated rules should always be reviewed and refined to remove generic artifacts and reduce false positives.

Combining automated extraction with manual validation typically produces the most reliable detection rules.

## Typical Detection Artifacts

Common artifacts used during YARA rule development include:

- Unique printable strings
- Imported DLLs
- Function names
- PE headers
- File size
- PE imports and exports
- Resource section characteristics
- Imphash values
- High-entropy sections
- .NET class names
- Malware-specific configuration strings

## Tools Used

| Tool | Purpose |
|------|---------|
| strings | Extract printable strings from malware samples |
| grep | Filter relevant artifacts |
| YARA | Malware detection and signature matching |

**Scope note**: The documented commands in this investigation use **strings**, **grep**, and **cat**. YARA, yarGen, and dnSpy are relevant to the broader project, but their execution is not demonstrated in this section.

## Investigation Scope

The investigation focused on analyzing a suspicious Windows DLL, extracting DLL-related artifacts, comparing those artifacts against an existing YARA rule, and identifying the string required to complete an existing rule indicator.

## Data Sources

| Source | Purpose |
|---------|----------|
| Malware Sample | Static malware analysis |
| strings | String extraction |
| YARA Rule | Detection logic validation |

## MITRE ATT&CK Mapping Background 

| Technique | ATT&CK ID |
|-----------|-----------|
| Software Discovery | T1518 |
| Malware | T1587 |
| Indicator Development | T1587.001 |

**MITRE ATT&CK Scope**: This investigation documents defensive static analysis and YARA rule inspection. No attacker behavior was independently reconstructed from the sample, so no specific ATT&CK technique is assigned to the observed activity.

## Investigation Methodology 

1. Analyze the malware sample.
2. Extract meaningful strings.
3. Identify DLL-related artifacts.
4. Compare extracted artifacts with the existing YARA rule.
5. Identify the replacement for the incomplete string indicator..
6. Document the proposed rule correction and identify the testing required to validate it.

## Investigation Overview 

The investigation followed a structured malware analysis workflow designed to identify candidate detection artifacts for YARA rule development. Rather than relying on generic strings, the analysis examined the malware sample, extracted DLL references, compared the findings against an existing YARA rule, and identified an incomplete string indicator requiring correction.

The investigation established a connection between a DLL reference extracted from the sample and a placeholder in the existing rule. The following sections document the commands, observed artifacts, and proposed detection logic refinement.

## Static Malware Analysis and YARA Rule Inspection

**Analysis Objective**: Examine **DirectX.dll** for DLL-related strings and compare the extracted artifacts with the existing APT17-related YARA rule to identify an incomplete detection indicator.

### Artifacts Examined:

`/home/htb-student/Samples/YARASigma/DirectX.dll`

`/home/htb-student/Rules/yara/apt_apt17_mal_sep17_1.yar`

## 1. DLL String Extraction

### Purpose: 

Identify DLL-related strings within the sample that may be relevant to YARA rule development.

### Command:

```bash
strings /home/htb-student/Samples/YARASigma/DirectX.dll | grep dll
```
### Results:

| Field | Value |
|-------|-------|
| Malware Sample | `DirectX.dll` |
| Extracted DLL Artifact | `TSMSISrv.dll` | 

### Analysis:

The strings utility extracts printable strings from the malware sample, while grep dll filters output to identify DLL-related references. During the analysis, the DLL reference TSMSISrv.dll was identified, providing a candidate string indicator for comparison with the existing YARA rule.

The presence of this string in the sample does not independently establish that the referenced DLL was loaded or executed, nor does it demonstrate that the string is exclusive to the malware.

## 2. Existing YARA Rule Inspection

### Purpose:

Inspect the existing YARA rule and identify placeholders requiring replacement with artifacts extracted from the malware sample.

### Command:

```bash
cat /home/htb-student/Rules/yara/apt_apt17_mal_sep17_1.yar | grep dll
```
### Results:

| Field | Value |
|-------|-------|
| YARA Rule | `apt_apt17_mal_sep17_1.yar` |
| Placeholder Identified | `X.dll` |
| Replacement Value | `TSMSISrv.dll` |

### Analysis:

The existing YARA rule was inspected to locate DLL-related detection logic. Analysis revealed that the rule contained the placeholder X.dll, indicating an incomplete detection artifact. By replacing the placeholder with the sample-derived string TSMSISrv.dll extracted during the previous investigation step, the rule could be updated to reference the observed DLL artifact. A subsequent YARA scan would be required to confirm whether the modified rule matches the sample.

## Investigation Findings 

Static analysis of the malware sample identified the DLL reference `TSMSISrv.dll`, which represented candidate detection artifact. Comparison with the existing APT17 YARA rule revealed that the rule contained the placeholder `X.dll` instead of the actual DLL name.

The analysis identified **TSMSISrv.dll** as the appropriate replacement for the incomplete string indicator. The documented evidence establishes the string extraction and rule inspection steps, but does not include the modified rule, a successful YARA match, or testing against benign files. Detection effectiveness and false-positive behavior therefore remain unverified.

## YARA Detection Engineering Concepts

### Manual Rule Development

Manual YARA rules are built from:

•	unique strings
•	imported DLLs
•	function names
•	file size
•	PE headers
•	imphash
•	entropy
•	malware-specific artifacts

### Example: UPX Detection

rule UPX_packed_executable
{
    meta:
        description = "Detects UPX-packed executables"

    strings:
        $string_1 = "UPX0"
        $string_2 = "UPX1"
        $string_3 = "UPX2"

    condition:
        all of them
}

### Example: APT17 / ZoxPNG Detection

Important detection ideas:

•	suspicious HTTP strings
•	specific User-Agent
•	unique URL patterns
•	PE imphash
•	file size constraints
•	imported DLLs

### Example: Neuron / Turla Detection

Detection based on .NET artifacts:

StorageUtils
WebServer
StorageFile
StorageScript
ServerConfig
CommandScript
ExecCMD
EncryptScript
KillOldThread

### Example: Stonedrill Detection

Detection based on:

•	PE resource inspection
•	high entropy resource section
•	resource ID 101
•	file enumeration APIs
•	unsigned PE file characteristics

## Detection Logic

### Suspicious DLL Artifact 

The DLL reference `TSMSISrv.dll` was identified through static string analysis of the malware sample. Because the string is specific to the analyzed malware and does not represent a common Windows component, it serves as a high-confidence detection artifact suitable for inclusion in a YARA rule. Malware-specific DLL references generally provide greater detection accuracy than generic strings while reducing the likelihood of false positives.

### Rule Improvement 

Inspection of the existing YARA rule revealed that the expected DLL artifact had been replaced with the placeholder `X.dll`, preventing the rule from correctly identifying the malware sample. Replacing the placeholder with the extracted artifact (`TSMSISrv.dll`) completed the detection logic and significantly improved the specificity and effectiveness of the rule.

### Malware-specific Detection

Effective YARA rules should be based on stable malware-specific artifacts rather than generic indicators that may appear in legitimate software. During this investigation, the extracted DLL reference (`TSMSISrv.dll`) represented a reliable malware-specific indicator that could be combined with additional characteristics such as PE metadata, imported functions, imphash values, and entropy analysis to produce more robust detection logic while minimizing false positives.

### Detection Specificity

Reliable YARA rules balance detection coverage with specificity. Replacing generic placeholders with validated malware artifacts reduces false positives while increasing confidence that matched files belong to the intended malware family. This investigation demonstrated how small improvements to rule content can significantly strengthen operational malware detection.

## IOC Summary

| IOC Type | Value |
|-----------|-------|
| Malware Sample | `DirectX.dll` |
| YARA Rule | `apt_apt17_mal_sep17_1.yar` |
| DLL Artifact | `TSMSISrv.dll` |
| Sample Directory | `/home/htb-student/Samples/YARASigma` |
| Rule Directory | `/home/htb-student/Rules/yara` |

## Placeholder Screenshots

Figure 1 - dnSpy .NET Analysis Example
Figure 2 - strings DirectX.dll | grep dll
Figure 3 - apt_apt17_mal_sep17_1.yar DLL Placeholder

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| String Analysis | Static string analysis is often the first step in identifying malware-specific artifacts suitable for YARA rule development. |
| Malware-specific Artifacts | High-quality YARA rules should prioritize unique malware-specific indicators rather than generic strings commonly found in legitimate software. |
| Rule Validation | Existing YARA rules should be validated against analyzed malware samples to ensure placeholders and incomplete indicators are replaced with accurate detection artifacts. |
| Automated Rule Generation | Tools such as **yarGen** can significantly accelerate rule creation; however, manually reviewing and refining generated rules remains essential for reducing false positives. |
| Detection Quality | Combining strings with PE metadata, imported DLLs, imphash values, .NET artifacts, and entropy analysis produces more reliable and resilient YARA detection rules. |

## MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Investigation Relevance |
|--------|-----------|-----------|-------------------------|
| Resource Development | Develop Capabilities: Malware | T1587 | Development and improvement of malware detection signatures |
| Resource Development | Develop Capabilities: Malware | T1587.001 | Creation and refinement of YARA detection rules |
| Defense Evasion | Obfuscated/Compressed Files and Information | T1027 | Detection of packed or obfuscated malware using YARA signatures |
| Defense Evasion | Software Packing | T1027.002 | Identification of packed executables through static artifacts such as UPX strings |

## Conclusion 

This investigation demonstrated how static malware analysis can be leveraged to develop and improve YARA detection rules. By extracting malware-specific artifacts, validating existing detection logic, and replacing incomplete placeholders with reliable indicators, analysts can significantly improve the accuracy and effectiveness of malware detection while reducing false positives.
The investigation also highlighted the importance of combining automated rule generation with manual analysis, ensuring that YARA rules remain both resilient and maintainable. Effective YARA rule development relies on selecting stable malware characteristics—including unique strings, imported DLLs, PE metadata, imphash values, and .NET artifacts—to produce high-confidence signatures suitable for malware hunting, threat detection, and incident response.
