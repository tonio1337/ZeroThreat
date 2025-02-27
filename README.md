# README for System Scan & Malware Analysis

## Overview
This document details the process of scanning a system for potential trojans, viruses, and malware. It includes recommended tools, scan techniques, and best practices for detecting and mitigating threats.

## Tools Used
- **Windows Defender** (Full Scan & Offline Scan)
- **Malwarebytes** (Trojan detection)
- **ESET Online Scanner** (Cloud-based malware analysis)
- **Process Explorer** (Check running processes)
- **Autoruns** (Review startup programs)
- **Wireshark/TCPView** (Network traffic analysis)

## File Extensions to Scan
- **Executables**: `.exe`, `.bat`, `.cmd`, `.msi`, `.scr`, `.com`
- **Scripts**: `.vbs`, `.js`, `.ps1`, `.wsf`, `.sh`
- **Documents**: `.docx`, `.xlsx`, `.pptx`, `.pdf` (Macro viruses)
- **Archives**: `.zip`, `.rar`, `.iso` (Malware-packed files)
- **System Files**: `.dll`, `.sys`, `.drv` (Rootkits, hidden malware)

## Steps to Run a System Scan
1. **Run a Full System Scan** using Windows Defender or Malwarebytes.
2. **Analyze Running Processes** with Process Explorer to identify suspicious activity.
3. **Check Startup Programs** with Autoruns for unwanted persistence mechanisms.
4. **Monitor Network Traffic** using Wireshark or TCPView.
5. **Quarantine & Remove Threats**, then reboot into **Safe Mode** for further investigation.

## Additional Notes
- Always update antivirus definitions before scanning.
- Use a **sandbox** or **virtual machine** for analyzing unknown files.
- Be cautious of **false positives**—cross-check results with VirusTotal.
