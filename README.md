# 🔍 Ransomware Forensic Simulation & DFIR Analysis Report

## 1. Executive Summary
* **What:** Simulated ransomware encryption attack for DFIR education.
* **Where:** Isolated Ubuntu VM on a Host-Only network layout.
* **When:** July 6, 2026.
* **Impact:** Successfully targeted and encrypted 22 critical files, generated forensic timeline artifacts, and established threat detection rules.

---

## 2. Lab Environment Setup
* **Host Infrastructure:** Dell Workstation hosting VMware Workstation.
* **Attacker Machine:** Kali Linux (Analysis platform running Streamlit Forensics Dashboard).
* **Victim Machine:** Ubuntu Desktop (Target simulation environment).
* **Network Isolation:** Host-only configuration (`192.168.159.0/24`) ensuring zero internet leakage.

---

## 3. Forensic Artifacts Recovered & Analyzed

### 📊 Dashboard Overview
*(We will insert your dashboard screenshot here in the next step!)*[Ransomware Forensics Dashboard.pdf](https://github.com/user-attachments/files/30006568/Ransomware.Forensics.Dashboard.pdf)


### 🔐 Cryptographic Summary
* **Algorithm:** AES-256 (Fernet symmetric encryption).
* **Session Key:** `a3e7cc09df299a2cfde39350b7ade925c1a93b29d75c3f3e625f79e7f09944da`
* **Key Format:** 64-character hexadecimal string.

### ⏱️ Attack Timeline
* **Execution Window:** Started at `18:38:36 UTC` and completed within roughly 60 seconds.
* **Encryption Signature:** Files were processed sequentially at an aggressive speed of approximately **0.5 seconds per file**.
* **Indicators of Compromise (IOCs):** All targeted files appended with `.locked` extensions and original data completely deleted.

---

## 4. Automated Threat Detection (YARA)
To identify this ransomware strain dynamically across an enterprise network, we deployed the following signature-based YARA rule:

```yara
rule Ransomware_Sim_Detection {
    meta:
        description = "Detects simulated ransomware indicators"
        author = "DFIR Student"
        date = "2026-07-06"
    strings:
        $note = "README_RESTORE" ascii
        $ext = ".locked" ascii
        $key_pattern = /[a-f0-9]{64}/ ascii
    condition:
        any of them
}
