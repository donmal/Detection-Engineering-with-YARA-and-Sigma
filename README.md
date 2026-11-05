# Detection Engineering with YARA and Sigma

## Overview

This project documents a series of practical Detection Engineering investigations focused on developing, validating, and operationalizing detection logic using **YARA** and **Sigma**. Through hands-on malware analysis, memory forensics, Windows Event Log analysis, and offline threat hunting, the project demonstrates how detection rules can be created, improved, translated, and validated across multiple platforms and tools.

The investigations cover both **signature-based detection** using YARA and **behavior-based detection** using Sigma, providing practical experience with static malware analysis, Windows telemetry, detection engineering, and threat hunting workflows.

---

## Project Objectives

The primary objectives of this project are to:

- Develop and improve YARA detection rules through malware analysis.
- Perform static analysis of Windows malware samples.
- Detect malware both on disk and within process memory.
- Hunt malware artifacts inside memory dumps using Volatility.
- Develop and validate Sigma detection rules.
- Translate Sigma rules into PowerShell and Splunk SPL.
- Execute Sigma rules using Chainsaw against offline Windows Event Logs.
- Detect Windows Defender abuse, PowerShell activity, ransomware behavior, and suspicious file creation events.
- Apply Detection Engineering concepts using practical investigation workflows.
- Map detection logic to the MITRE ATT&CK framework.

---

## Skills Demonstrated

### YARA Detection Engineering

- Manual YARA rule development
- Automated rule generation with yarGen
- Static malware analysis
- PE file inspection
- .NET assembly analysis using dnSpy
- String extraction
- Malware-specific artifact selection
- Hexadecimal pattern creation
- Rule tuning and validation
- Memory-based malware hunting

### Sigma Detection Engineering

- Sigma rule development
- Sigma rule translation using sigmac
- PowerShell query generation
- Splunk SPL generation
- Offline Windows Event Log hunting
- Chainsaw investigations
- Windows Defender detection analysis
- PowerShell Script Block analysis
- Windows Event ID correlation

### Threat Hunting

- Malware detection
- Memory forensics
- Offline EVTX investigations
- Process memory analysis
- Windows Defender hunting
- Ransomware detection
- Shadow Volume Copy deletion detection
- Archive creation hunting
- Post-exploitation artifact identification

---

## Tools Used

| Category | Tools |
|----------|-------|
| Detection Engineering | YARA, Sigma, yarGen |
| Sigma Translation | sigmac |
| Threat Hunting | Chainsaw, Splunk |
| Malware Analysis | dnSpy, HxD, strings |
| Memory Forensics | Volatility, yarascan |
| Windows Analysis | Get-WinEvent, Windows Defender Logs |
| Operating Systems | Windows, Linux |

---

## Investigation Modules

### 01 – Developing YARA Rules

Developing and improving YARA rules through static malware analysis by extracting meaningful strings and replacing weak placeholders with malware-specific detection artifacts.

**Topics Covered**

- Manual YARA rule development
- PE inspection
- .NET malware analysis
- Rule tuning
- False-positive reduction

---

### 02 – Hunting Evil with YARA (Windows)

Using YARA to detect malware both on disk and inside running process memory while improving an existing YARA rule through hexadecimal string analysis.

**Topics Covered**

- Process memory scanning
- Hexadecimal pattern generation
- Shellcode detection
- ETW hunting
- Memory-based malware detection

---

### 03 – Hunting Evil with YARA (Linux)

Applying YARA and Volatility to investigate memory dumps, identify ransomware artifacts, and attribute malicious behavior through memory forensics.

**Topics Covered**

- Volatility
- yarascan
- Memory hunting
- WannaCry investigation
- Shadow Copy deletion analysis

---

### 04 – Developing Sigma Rules

Translating Sigma rules into executable PowerShell detections and validating them against Windows Event Logs.

**Topics Covered**

- Sigma rule development
- sigmac
- Windows Defender detections
- EVTX investigations
- Offline log analysis

---

### 05 – Hunting Evil with Sigma (Chainsaw)

Executing Sigma rules using Chainsaw to perform offline threat hunting against Windows Event Logs.

**Topics Covered**

- Chainsaw
- Event ID 4104
- PowerShell Script Block Logging
- Windows Defender exclusions
- Defense evasion detection

---

### 06 – Hunting Evil with Sigma (Splunk)

Translating Sigma rules into Splunk SPL and validating detections using Windows telemetry ingested into Splunk.

**Topics Covered**

- Splunk SPL
- Sigma translation
- File creation analysis
- Archive detection
- Detection validation

---

### 07 – Detection Engineering Capstone

A practical capstone assessment combining YARA rule development with Sigma-based threat hunting to simulate real-world Detection Engineering tasks.

**Assessment Part I**

- .NET malware analysis
- Seatbelt detection
- YARA rule improvement

**Assessment Part II**

- Chainsaw hunting
- Sigma rule execution
- Shadow Volume Copy deletion detection
- PowerShell analysis

---

## MITRE ATT&CK Coverage

The project demonstrates detections mapped to multiple ATT&CK tactics and techniques, including:

### Execution

- T1059.001 – PowerShell

### Defense Evasion

- T1070 – Indicator Removal on Host

### Discovery

- Windows reconnaissance
- System and file discovery

### Collection

- Archive Collected Data (T1560.001)

### Impact

- T1490 – Inhibit System Recovery

### Malware

- Signature-based malware detection
- Behavioral malware detection
- Memory-resident malware detection

---

## Detection Engineering Concepts

Throughout the project, the following concepts are demonstrated:

- Static malware analysis
- Detection engineering lifecycle
- Signature development
- Rule validation
- Detection tuning
- Detection testing
- Memory hunting
- Event log hunting
- Windows telemetry analysis
- Offline investigations
- Threat hunting methodologies
- IOC identification
- Detection logic development
- Detection engineering best practices

---

## Repository Structure

```
Detection-Engineering-with-YARA-and-Sigma/
│
├── 01-Developing-YARA-Rules.md
├── 02-Hunting-Evil-with-YARA-Windows.md
├── 03-Hunting-Evil-with-YARA-Linux.md
├── 04-Developing-Sigma-Rules.md
├── 05-Hunting-Evil-with-Sigma-Chainsaw.md
├── 06-Hunting-Evil-with-Sigma-Splunk.md
├── 07-Detection-Engineering-Capstone.md
│
└── README.md
```

---

## Key Takeaways

This project demonstrates how Detection Engineering extends beyond writing individual detection rules. Effective detection requires understanding malware behavior, selecting reliable detection artifacts, validating rules against real telemetry, and continuously refining detection logic across multiple platforms. By combining YARA, Sigma, Chainsaw, Splunk, and memory forensics, the investigations illustrate practical workflows used by SOC analysts and Detection Engineers to identify malware, validate detections, and improve defensive capabilities within enterprise environments.

