# ForensiX Pro

**Enterprise-Grade Windows Digital Forensics & Incident Response Suite**

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011-0078D6.svg)](https://www.microsoft.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GUI Framework](https://img.shields.io/badge/GUI-PyQt5%20Light%20Theme-6366f1.svg)](https://www.riverbankcomputing.com/software/pyqt/)
[![Version](https://img.shields.io/badge/Version-v2.0.0%20Pro-2563eb.svg)](VERSION_INFO.txt)
[![Build](https://img.shields.io/badge/Release-September%202026-10b981.svg)](VERSION_INFO.txt)

---

## Executive Overview

**ForensiX Pro** is a high-performance digital forensics investigation platform engineered for cyber incident responders, forensic examiners, and security auditors. Built from the ground up to operate with minimal CPU and RAM overhead, ForensiX Pro provides end-to-end evidence discovery, binary metadata extraction, multi-profile browser auditing, chronological event correlation, cryptographic chain of custody preservation, and court-ready HTML/CSV reporting.

---

## Key Modules & Capabilities

```
+-----------------------------------------------------------------------------------+
|                                   ForensiX Pro                                    |
+---------------------+---------------------+------------------+--------------------+
| File Recovery Engine| Log Analyzer        | Timeline Creator | Evidence Collector |
| - $I/$R Binary      | - Security/System   | - 0% Drop Date   | - SHA-256 Chain    |
|   Metadata Parser   |   Event Logs (.evtx)|   Parsing        |   of Custody       |
| - 1-Click File      | - Multi-Profile     | - Chronological  | - ZIP & Folder     |
|   Restoration       |   Browser Extractor |   Correlation    |   Packaging        |
| - Low-Level Disk MFT|   (Chrome/Edge/FF)  | - Unified Sort   | - JSON Metadata    |
+---------------------+---------------------+------------------+--------------------+
|                                Dual Reporting Engine                              |
|          - Interactive Responsive Web HTML  |  - Structured RFC-4180 CSV          |
+-----------------------------------------------------------------------------------+
```

### 1. File Recovery & Recycle Bin Engine
* **Windows Binary `$I`/`$R` Parser**: Directly parses Vista/Win7 (`$I` v1 - 544 bytes) and Windows 10/11 (`$I` v2 - 544+ bytes) binary headers to extract original file paths, deletion timestamps (Windows FILETIME 64-bit format), and file sizes.
* **Direct File Restoration**: Restores files from Recycle Bin back to their original file path or a designated target directory.
* **NTFS & Disk Artifact Scanner**: Efficiently locates residual deleted artifacts and temporary file fragments with chunked SHA-256 hash generation.

### 2. Multi-Profile Browser & Event Log Analyzer
* **Interactive Profile Selector**: Automatically detects all browser profiles (Default, Profile 1, Profile 2, Guest, etc.) across Chrome, Microsoft Edge, Mozilla Firefox, Brave, and Opera. Allows selective extraction per profile or unified extraction across all profiles.
* **Non-Locking SQLite Extraction**: Employs read-only shadow buffers to safely read live browser history databases without crashing active browser processes.
* **Windows Event Log Parser**: Extracts Application, Security, and System `.evtx` event logs using optimized PowerShell pipelines with flexible date handling.

### 3. Unified Forensic Timeline Creator
* **Zero-Drop Universal Timestamp Normalization**: Standardizes dates across diverse formats (`/Date(...)`, ISO-8601, Unix epoch timestamps, Chrome WebKit epoch microseconds, PRTime milliseconds, and standard datetime formats) with zero dropped events.
* **Cross-Source Activity Mapping**: Chronologically correlates file modifications, user logins, browser navigation, and system service state changes.

### 4. Cryptographic Evidence Collector
* **Chain of Custody Tracking**: Records investigator identity, case ID, acquisition timestamps, original file metadata, and tamper-proof SHA-256 cryptographic hashes.
* **Export Packages**: Generates legally defensible evidence packages in structured ZIP archives or standardized directory structures with machine-readable `chain_of_custody.json` records.

### 5. Dual Reporting Engine
* **Interactive Web-Responsive HTML Reports**: Produces self-contained, CSS-grid formatted reports that render cleanly across all web browsers (Chrome, Edge, Firefox, Safari) and print-to-PDF without clipped columns or squashed text.
* **Machine-Readable CSV Exports**: Structured RFC-4180 compliant CSV files ready for ingestion into SIEM platforms, Excel, or analytical pipelines.

---

## Architectural Highlights

* **Asynchronous Multithreading (`QThread`)**: All intensive I/O operations (MFT scanning, log parsing, SHA-256 hashing) run on background worker threads, ensuring the desktop GUI stays 100% responsive.
* **Ultra-Low Memory Footprint**: Utilizes streaming database cursors and 64KB chunked file hashing, preventing memory spikes even when processing tens of thousands of artifacts.
* **Modern Light Theme GUI**: Clean, distraction-free interface with resizable splitter sidebars, custom column widths, and an interactive **Double-Click Cell Inspector** dialog to view and copy long file paths and event payloads.

---

## System Requirements

| Specification | Minimum | Recommended |
|---|---|---|
| **Operating System** | Windows 10 (64-bit) | Windows 10 / 11 (64-bit) |
| **Python Version** | Python 3.8+ | Python 3.10 / 3.11 / 3.12 / 3.14 |
| **Memory (RAM)** | 2 GB | 4 GB+ |
| **Disk Space** | 100 MB free | 1 GB+ (for evidence staging) |
| **Privileges** | Standard User | Administrator (for Security Event Logs) |

---

## Installation & Quick Start

### Method 1: One-Click Setup (Recommended for Windows)

Double-click `one_click_setup.bat` or run:
```cmd
one_click_setup.bat
```
This automatically verifies your Python environment, installs the required dependencies, and launches the ForensiX Pro GUI.

### Method 2: Manual Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Kunal-CodeLab/ForensiX-Pro.git
   cd ForensiX-Pro
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Launch the Application:**
   ```bash
   python launch_gui.py
   ```

---

## Automated Test Suite

ForensiX Pro includes a self-contained validation test suite that verifies all core forensic modules, binary parsers, date normalizers, and reporting engines:

```bash
python test_forensic_tool.py
```

### Test Coverage:
* `[+]` System Compatibility & Dependency Check
* `[+]` File Recovery Engine ($I/$R binary parser & restoration test)
* `[+]` Log Analyzer (Event logs & multi-profile browser discovery)
* `[+]` Timeline Creator (Cross-source timestamp correlation)
* `[+]` Evidence Collector (SHA-256 verification & ZIP/folder packaging)
* `[+]` Report Generator (CSV export & HTML report layout test)

---

## Repository Structure

```
ForensiX-Pro/
├── forensic_analysis_tool.py   # Core Forensic Engine & PyQt5 GUI
├── launch_gui.py               # Safe Launcher with High-DPI Scaling
├── launch_gui.bat              # Quick Windows Batch Launcher
├── one_click_setup.bat         # Automated Setup & Dependency Installer
├── run_forensic_tool.bat       # Standalone Run Script
├── test_forensic_tool.py       # Automated Verification Test Suite
├── requirements.txt            # Python Dependencies
├── VERSION_INFO.txt            # Release Metadata & Specifications
├── LICENSE                     # MIT Open Source License
└── README.md                   # Technical Documentation
```

---

## Forensic Integrity & Legal Compliance

* **Read-Only / Non-Destructive**: All forensic scanning functions perform read-only queries on system artifacts to protect evidence integrity.
* **Cryptographic Hashing**: SHA-256 checksums are calculated using standard chunked streams at the exact moment of acquisition.
* **Audit Trail**: Every evidence item includes acquisition timestamps, source host metadata, file size in bytes, and chain of custody documentation.

## Author & Maintainer

* **Kunal Choudhary** &mdash; *Creator & Lead Developer*
  * GitHub: [@Kunal-CodeLab](https://github.com/Kunal-CodeLab)

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

**ForensiX Pro** &mdash; *Engineered for precision digital forensics & incident response by Kunal Choudhary.*
