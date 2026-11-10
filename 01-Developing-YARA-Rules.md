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

### Figure 1 - DLL String Extraction 

![Figure 1 - DLL String Extraction](../images/developing-yara-rules/dll-string-extraction.png)

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

### Figure 2 - Existing YARA Rule Inspection 

![Figure 2 - Existing YARA Rule Inspection](../images/developing-yara-rules/existing-yara-rule-inspection.png)

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

These artifacts can be combined into detection conditions to improve rule specificity. Their reliability depends on how distinctive they are and whether the resulting rule is validated against representative samples.

## Detection Logic

### Suspicious DLL Artifact 

The DLL reference `TSMSISrv.dll` was identified through static string analysis of the malware sample. 

The extracted string represents a candidate detection indicator relevant to the existing YARA rule. Its presence in the sample provides evidence for the proposed rule correction, although additional testing would be required to establish its uniqueness and reliability across malicious and benign files.

### Rule Improvement 

Inspection of the existing YARA rule revealed that the expected DLL artifact had been replaced with the placeholder `X.dll`. 

This indicated that the rule contained an incomplete string indicator requiring correction.

Replacing the placeholder with the extracted artifact (`TSMSISrv.dll`) was identified as the appropriate modification based on the sample analysis. The documented commands establish the relationship between the extracted string and the rule placeholder, but do not demonstrate a successful YARA scan after modification.

### Malware-specific Detection

Effective YARA rules should be based on stable malware-specific artifacts rather than generic indicators that may appear in legitimate software. 

During this investigation, the extracted DLL reference ( TSMSISrv.dll ) represented candidate detection indicator that could be combined with additional characteristics such as PE metadata, imported functions, imphash values and entropy analysis to produce more robust detection logic after appropriate testing and validation.

### Detection Validation and Limitations

Reliable YARA rules balance detection coverage with specificity. 

The investigation identified a more relevant string for the existing rule, but did not document a completed YARA execution or false-positive assessment. Further validation would require scanning the reference sample, reviewing the full rule conditions, and testing the rule against unrelated malicious and benign files.

The extracted string should therefore be treated as a candidate detection artifact rather than a fully validated malware signature.

## Investigation Artifacts and Candidate IOC 

| IOC Type | Value |
|-----------|-------|
| Malware Sample | `DirectX.dll` |
| YARA Rule | `apt_apt17_mal_sep17_1.yar` |
| DLL Artifact | `TSMSISrv.dll` |
| Sample Directory | `/home/htb-student/Samples/YARASigma` |
| Rule Directory | `/home/htb-student/Rules/yara` |

**Note**: The table contains both investigation artifacts and a candidate detection indicator. The local sample and rule paths are not themselves indicators of compromise. The extracted DLL reference requires additional corroboration before being treated as a high-confidence IOC.

## Lessons Learned

| Lesson | Description |
|---------|-------------|
| String Analysis | Static string analysis is often the first step in identifying malware-specific artifacts suitable for YARA rule development. |
| Malware-specific Artifacts | High-quality YARA rules should prioritize unique malware-specific indicators rather than generic strings commonly found in legitimate software. |
| Rule Validation | Inspecting existing rules can identify incomplete indicators, but successful detection must be verified through rule execution and testing against representative samples |
| Detection Quality | Combining distinctive strings with additional PE characteristics can strengthen detection logic, provided the final rule is tested for detection coverage and false positives. |

## Conclusion 

This investigation demonstrated how static malware analysis can be leveraged to support the refinement of YARA detection rules. 

By extracting DLL-related strings from **DirectX.dll** and inspecting the existing APT17-related YARA rule, the investigation identified **TSMSISrv.dll** as the appropriate replacement for an incomplete string indicator.

The findings demonstrate the value of correlating sample-derived artifacts with existing detection logic. However, successful rule matching and false-positive performance were not verified in the documented evidence.

The investigation reinforces the importance of selecting meaningful detection indicators, reviewing rule conditions, and validating proposed changes before considering a YARA signature suitable for operational use.

