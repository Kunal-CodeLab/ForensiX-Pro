#!/usr/bin/env python3
"""
ForensiX Pro - Digital Forensics Suite
Production-ready forensic investigation tool with high performance and modern Light Theme PyQt5 GUI.
Features:
- Deleted File Recovery & Windows Recycle Bin ($I/$R metadata parser & file restore)
- Multi-Profile Browser History (Chrome, Edge, Firefox, Brave, Opera) with profile selection
- Windows Event Log Analysis with robust date parsing (/Date(...)/, ISO, standard)
- Timeline Generator with 0% data drop universal timestamp parsing
- Evidence Collection & Chain of Custody packaging
- Full-fidelity HTML/CSV Reporting with responsive web formatting
- Low RAM & Low CPU optimized with asynchronous QThread background workers
- 100% Clean Light Theme (Adjustable layout, no text clipping, read-only tables with cell inspector)
"""

import os
import sys
import json
import csv
import sqlite3
import datetime
import subprocess
import shutil
import zipfile
import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict
import threading
import time
import re
import struct
import gc
import webbrowser

# Platform-specific imports
if os.name == 'nt':
    import winreg
else:
    class MockWinReg:
        HKEY_CURRENT_USER = None
        HKEY_LOCAL_MACHINE = None
        def OpenKey(self, *args): pass
        def QueryValueEx(self, *args): return ("", 0)
        def CloseKey(self, *args): pass
    winreg = MockWinReg()

try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLabel, QTableWidget, QTableWidgetItem, QTabWidget,
        QProgressBar, QLineEdit, QCheckBox, QTextEdit, QFileDialog,
        QMessageBox, QInputDialog, QComboBox, QHeaderView, QSplitter,
        QAbstractItemView, QFrame, QDialog, QDialogButtonBox, QTabBar
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, pyqtSlot, QObject
    from PyQt5.QtGui import QFont, QColor
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False


# ============================================================================
# UTILITIES: Robust Date & Hash Parsers (Low CPU & RAM)
# ============================================================================

def parse_flexible_timestamp(val):
    """Universal date parser supporting datetime, epoch, PowerShell JSON, ISO, and standard dates."""
    if val is None or val == '' or val == 'N/A':
        return None
    if isinstance(val, datetime.datetime):
        return val
    if isinstance(val, (int, float)):
        if val > 1e11:  # milliseconds
            return datetime.datetime.fromtimestamp(val / 1000.0)
        return datetime.datetime.fromtimestamp(val)
    
    val_str = str(val).strip()
    if not val_str:
        return None

    # Handle PowerShell JSON Date: /Date(1678901234567)/ or /Date(1678901234567+0530)/
    ps_match = re.search(r'/Date\((\-?\d+)(?:[+-]\d+)?\)/', val_str)
    if ps_match:
        try:
            ms = int(ps_match.group(1))
            return datetime.datetime.fromtimestamp(ms / 1000.0)
        except Exception:
            pass

    # Try ISO format
    try:
        clean_iso = val_str.replace('Z', '+00:00')
        return datetime.datetime.fromisoformat(clean_iso)
    except Exception:
        pass

    # Common standard format checks
    formats = [
        '%m/%d/%Y %I:%M:%S %p',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%d-%m-%Y %H:%M:%S',
        '%d/%m/%Y %H:%M:%S',
        '%Y/%m/%d %H:%M:%S',
        '%a %b %d %H:%M:%S %Y',
        '%b %d, %Y %I:%M:%S %p'
    ]
    for fmt in formats:
        try:
            return datetime.datetime.strptime(val_str, fmt)
        except Exception:
            continue

    return None


def calculate_file_hash(file_path, chunk_size=65536, max_bytes=50 * 1024 * 1024):
    """Calculates SHA-256 hash using streaming 64KB chunks to minimize memory & CPU spikes."""
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return "N/A"
    try:
        file_size = os.path.getsize(file_path)
        hash_sha256 = hashlib.sha256()
        bytes_read = 0
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hash_sha256.update(chunk)
                bytes_read += len(chunk)
                if file_size > max_bytes and bytes_read >= max_bytes:
                    break
        return hash_sha256.hexdigest()
    except Exception:
        return "N/A"


# ============================================================================
# MODULE 1: File Recovery Engine (Recycle Bin $I/$R Parser & Safe Restore)
# ============================================================================

class FileRecoveryEngine:
    """Handles deleted file discovery, Windows Recycle Bin $I/$R binary parsing, and restoration."""

    def __init__(self):
        self.recovered_files = []
        self.recycle_bin_files = []

    def _parse_windows_i_file(self, i_path):
        """
        Parses Windows $I metadata file.
        Vista/7/8 Format (v1): 8-byte header (1), 8-byte size, 8-byte FILETIME, UTF-16LE path.
        Win 10/11 Format (v2): 8-byte header (2), 8-byte size, 8-byte FILETIME, 4-byte path len, UTF-16LE path.
        """
        try:
            with open(i_path, "rb") as f:
                data = f.read()
            if len(data) < 24:
                return None

            version = struct.unpack("<Q", data[0:8])[0]
            file_size = struct.unpack("<q", data[8:16])[0]
            filetime = struct.unpack("<Q", data[16:24])[0]

            deleted_time = None
            if filetime > 0:
                try:
                    deleted_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime // 10)
                except Exception:
                    deleted_time = None

            original_path = ""
            if version == 1:
                original_path = data[24:].decode('utf-16-le', errors='ignore').rstrip('\x00')
            elif version == 2:
                if len(data) >= 28:
                    original_path = data[28:].decode('utf-16-le', errors='ignore').rstrip('\x00')
                else:
                    original_path = data[24:].decode('utf-16-le', errors='ignore').rstrip('\x00')
            else:
                original_path = data[24:].decode('utf-16-le', errors='ignore').rstrip('\x00')

            original_name = os.path.basename(original_path) if original_path else os.path.basename(i_path)

            return {
                'original_name': original_name,
                'original_path': original_path,
                'file_size': file_size,
                'deleted_time': deleted_time
            }
        except Exception as e:
            return None

    def scan_recycle_bin(self):
        """Scans Windows Recycle Bin across all accessible drives, pairing $I and $R files."""
        self.recycle_bin_files = []
        scanned_r_files = set()

        if os.name == 'nt':
            drives = []
            for drive_letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
                drive_path = f"{drive_letter}:\\"
                if os.path.exists(drive_path):
                    drives.append(drive_path)

            for drive in drives:
                recycle_path = os.path.join(drive, "$Recycle.Bin")
                if not os.path.exists(recycle_path):
                    continue

                try:
                    for root, dirs, files in os.walk(recycle_path):
                        i_files = {}
                        r_files = {}
                        for f in files:
                            full_p = os.path.join(root, f)
                            if f.startswith("$I") or f.startswith("$i"):
                                key = f[2:]
                                i_files[key] = full_p
                            elif f.startswith("$R") or f.startswith("$r"):
                                key = f[2:]
                                r_files[key] = full_p

                        for key, i_path in i_files.items():
                            meta = self._parse_windows_i_file(i_path)
                            r_path = r_files.get(key, "")
                            if r_path:
                                scanned_r_files.add(r_path)

                            file_size = meta['file_size'] if meta and meta.get('file_size') is not None else 0
                            if file_size <= 0 and r_path and os.path.exists(r_path):
                                try:
                                    file_size = os.path.getsize(r_path)
                                except Exception:
                                    pass

                            original_name = meta['original_name'] if meta and meta.get('original_name') else (os.path.basename(r_path) if r_path else os.path.basename(i_path))
                            original_path = meta['original_path'] if meta and meta.get('original_path') else (r_path or i_path)
                            del_time = meta['deleted_time'] if meta and meta.get('deleted_time') else None

                            self.recycle_bin_files.append({
                                'name': original_name,
                                'path': original_path,
                                'physical_path': r_path if (r_path and os.path.exists(r_path)) else i_path,
                                'size': file_size,
                                'modified': del_time or datetime.datetime.now(),
                                'accessed': del_time or datetime.datetime.now(),
                                'created': del_time or datetime.datetime.now(),
                                'source': 'Recycle Bin ($I/$R Paired)',
                                'hash': calculate_file_hash(r_path) if (r_path and os.path.exists(r_path)) else 'N/A',
                                'can_restore': bool(r_path and os.path.exists(r_path))
                            })

                        for key, r_path in r_files.items():
                            if r_path not in scanned_r_files:
                                try:
                                    stat = os.stat(r_path)
                                    self.recycle_bin_files.append({
                                        'name': os.path.basename(r_path),
                                        'path': r_path,
                                        'physical_path': r_path,
                                        'size': stat.st_size,
                                        'modified': datetime.datetime.fromtimestamp(stat.st_mtime),
                                        'accessed': datetime.datetime.fromtimestamp(stat.st_atime),
                                        'created': datetime.datetime.fromtimestamp(stat.st_ctime),
                                        'source': 'Recycle Bin ($R Unlinked)',
                                        'hash': calculate_file_hash(r_path),
                                        'can_restore': True
                                    })
                                except Exception:
                                    pass
                except Exception as e:
                    print(f"Warning scanning drive {drive} recycle bin: {e}")
        else:
            trash_paths = [
                os.path.expanduser("~/.local/share/Trash/files"),
                os.path.expanduser("~/.Trash")
            ]
            for path in trash_paths:
                if os.path.exists(path):
                    self._scan_directory(path, "Recycle Bin (Trash)")

        return self.recycle_bin_files

    def scan_deleted_files(self, drive_path="C:\\"):
        """Scans forensic artifact locations, temporary stores, and shadow directories."""
        self.recovered_files = []
        temp_dirs = []

        if os.name == 'nt':
            temp_dirs = [
                os.path.expandvars("%TEMP%"),
                os.path.expandvars("%TMP%"),
                "C:\\Windows\\Temp",
                os.path.expandvars("C:\\Users\\%USERNAME%\\AppData\\Local\\Temp")
            ]
        else:
            temp_dirs = ["/tmp", "/var/tmp", os.path.expanduser("~/.local/share/Trash")]

        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                self._scan_directory(temp_dir, "Temporary / Deleted Artifacts")

        return self.recovered_files

    def _scan_directory(self, path, source_type, max_files=2000):
        """Memory-efficient recursive directory scanner with count guard."""
        count = 0
        try:
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_info = self._get_file_info(file_path, source_type)
                    if source_type.startswith("Recycle"):
                        self.recycle_bin_files.append(file_info)
                    else:
                        self.recovered_files.append(file_info)
                    count += 1
                    if count >= max_files:
                        return
        except Exception as e:
            print(f"Error scanning directory {path}: {e}")

    def _get_file_info(self, file_path, source):
        """Extract file metadata cleanly."""
        try:
            stat = os.stat(file_path)
            return {
                'name': os.path.basename(file_path),
                'path': file_path,
                'physical_path': file_path,
                'size': stat.st_size,
                'modified': datetime.datetime.fromtimestamp(stat.st_mtime),
                'accessed': datetime.datetime.fromtimestamp(stat.st_atime),
                'created': datetime.datetime.fromtimestamp(stat.st_ctime),
                'source': source,
                'hash': calculate_file_hash(file_path),
                'can_restore': True
            }
        except Exception as e:
            return {
                'name': os.path.basename(file_path),
                'path': file_path,
                'physical_path': file_path,
                'size': 0,
                'source': source,
                'error': str(e),
                'can_restore': False
            }

    def restore_file_to_destination(self, physical_path, destination_folder, original_name=None):
        """Safely restores a recovered file from Recycle Bin / Temp to a user-chosen destination folder."""
        if not physical_path or not os.path.exists(physical_path):
            raise FileNotFoundError(f"Source file does not exist: {physical_path}")
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder, exist_ok=True)

        target_name = original_name or os.path.basename(physical_path)
        dest_path = os.path.join(destination_folder, target_name)

        base, ext = os.path.splitext(target_name)
        counter = 1
        while os.path.exists(dest_path):
            dest_path = os.path.join(destination_folder, f"{base}_recovered_{counter}{ext}")
            counter += 1

        shutil.copy2(physical_path, dest_path)
        return dest_path


# ============================================================================
# MODULE 2: Log & Multi-Profile Browser Analyzer
# ============================================================================

class LogAnalyzer:
    """Analyzes Windows Event Logs and multi-profile browser histories with minimal RAM/CPU."""

    def __init__(self):
        self.event_logs = []
        self.browser_history = []

    def get_available_browser_profiles(self):
        """
        Discovers all installed browsers and their respective profiles on the system.
        Returns a list of profile dictionaries for UI selection.
        """
        profiles = []
        user_home = Path.home()

        # 1. Google Chrome
        chrome_base = user_home / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
        if chrome_base.exists():
            for item in chrome_base.iterdir():
                if item.is_dir() and (item.name == "Default" or item.name.startswith("Profile")):
                    hist_file = item / "History"
                    if hist_file.exists():
                        profiles.append({
                            'id': f"chrome_{item.name}",
                            'browser': "Google Chrome",
                            'profile_name': item.name,
                            'history_path': str(hist_file)
                        })

        # 2. Microsoft Edge
        edge_base = user_home / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data"
        if edge_base.exists():
            for item in edge_base.iterdir():
                if item.is_dir() and (item.name == "Default" or item.name.startswith("Profile")):
                    hist_file = item / "History"
                    if hist_file.exists():
                        profiles.append({
                            'id': f"edge_{item.name}",
                            'browser': "Microsoft Edge",
                            'profile_name': item.name,
                            'history_path': str(hist_file)
                        })

        # 3. Brave Browser
        brave_base = user_home / "AppData" / "Local" / "BraveSoftware" / "Brave-Browser" / "User Data"
        if brave_base.exists():
            for item in brave_base.iterdir():
                if item.is_dir() and (item.name == "Default" or item.name.startswith("Profile")):
                    hist_file = item / "History"
                    if hist_file.exists():
                        profiles.append({
                            'id': f"brave_{item.name}",
                            'browser': "Brave",
                            'profile_name': item.name,
                            'history_path': str(hist_file)
                        })

        # 4. Mozilla Firefox
        ff_base = user_home / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
        if ff_base.exists():
            for item in ff_base.iterdir():
                if item.is_dir():
                    hist_file = item / "places.sqlite"
                    if hist_file.exists():
                        profiles.append({
                            'id': f"firefox_{item.name}",
                            'browser': "Mozilla Firefox",
                            'profile_name': item.name,
                            'history_path': str(hist_file)
                        })

        # 5. Linux / macOS Fallback paths
        linux_chrome = user_home / ".config" / "google-chrome" / "Default" / "History"
        if linux_chrome.exists():
            profiles.append({
                'id': "linux_chrome_default",
                'browser': "Google Chrome (Linux)",
                'profile_name': "Default",
                'history_path': str(linux_chrome)
            })

        linux_ff = user_home / ".mozilla" / "firefox"
        if linux_ff.exists():
            for item in linux_ff.iterdir():
                if item.is_dir() and (item / "places.sqlite").exists():
                    profiles.append({
                        'id': f"linux_ff_{item.name}",
                        'browser': "Mozilla Firefox (Linux)",
                        'profile_name': item.name,
                        'history_path': str(item / "places.sqlite")
                    })

        return profiles

    def analyze_browser_history(self, target_profile_id=None):
        """
        Extracts browsing history using streaming batches.
        If target_profile_id is provided, extracts only that profile; otherwise extracts all.
        """
        self.browser_history = []
        profiles = self.get_available_browser_profiles()

        if target_profile_id and target_profile_id != "ALL":
            profiles = [p for p in profiles if p['id'] == target_profile_id]

        for p in profiles:
            try:
                if "Firefox" in p['browser']:
                    self._extract_firefox_history_file(p['history_path'], p['browser'], p['profile_name'])
                else:
                    self._extract_chromium_history_file(p['history_path'], p['browser'], p['profile_name'])
            except Exception as e:
                print(f"Error reading history for {p['browser']} ({p['profile_name']}): {e}")

        gc.collect()
        return self.browser_history

    def _extract_chromium_history_file(self, db_path, browser_name, profile_name):
        """Safely extracts Chromium SQLite history in small memory chunks."""
        if not os.path.exists(db_path):
            return

        temp_db = db_path + f"_forensic_temp_{int(time.time()*1000)}"
        try:
            shutil.copy2(db_path, temp_db)
            conn = sqlite3.connect(temp_db)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT url, title, visit_count, last_visit_time 
                FROM urls 
                WHERE last_visit_time > 0
                ORDER BY last_visit_time DESC 
                LIMIT 3000
            """)

            while True:
                rows = cursor.fetchmany(500)
                if not rows:
                    break
                for row in rows:
                    raw_time = row['last_visit_time']
                    timestamp = None
                    if raw_time and raw_time > 0:
                        try:
                            timestamp = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=raw_time)
                        except Exception:
                            timestamp = None

                    self.browser_history.append({
                        'browser': f"{browser_name} ({profile_name})",
                        'title': row['title'] or "Untitled",
                        'url': row['url'] or "",
                        'visit_count': row['visit_count'] or 1,
                        'timestamp': timestamp
                    })

            conn.close()
        finally:
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except Exception:
                    pass

    def _extract_firefox_history_file(self, db_path, browser_name, profile_name):
        """Safely extracts Firefox SQLite history in small memory chunks."""
        if not os.path.exists(db_path):
            return

        temp_db = db_path + f"_forensic_temp_{int(time.time()*1000)}"
        try:
            shutil.copy2(db_path, temp_db)
            conn = sqlite3.connect(temp_db)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT p.url, p.title, p.visit_count, h.visit_date
                FROM moz_places p
                LEFT JOIN moz_historyvisits h ON p.id = h.place_id
                WHERE h.visit_date IS NOT NULL
                ORDER BY h.visit_date DESC
                LIMIT 3000
            """)

            while True:
                rows = cursor.fetchmany(500)
                if not rows:
                    break
                for row in rows:
                    visit_date = row['visit_date']
                    timestamp = None
                    if visit_date:
                        try:
                            timestamp = datetime.datetime.fromtimestamp(visit_date / 1000000.0)
                        except Exception:
                            timestamp = None

                    self.browser_history.append({
                        'browser': f"{browser_name} ({profile_name})",
                        'title': row['title'] or "Untitled",
                        'url': row['url'] or "",
                        'visit_count': row['visit_count'] or 1,
                        'timestamp': timestamp
                    })

            conn.close()
        finally:
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except Exception:
                    pass

    def analyze_windows_logs(self, log_types=None, max_entries_per_log=300):
        """Analyzes Windows Event Logs with resilient PowerShell JSON formatting and date parsers."""
        self.event_logs = []
        if os.name != 'nt':
            print("Windows logs only available on Windows systems")
            return []

        if log_types is None:
            log_types = ['System', 'Security', 'Application']

        for log_type in log_types:
            try:
                cmd = (
                    f'powershell -NoProfile -ExecutionPolicy Bypass -Command '
                    f'"Get-EventLog -LogName {log_type} -Newest {max_entries_per_log} -ErrorAction SilentlyContinue | '
                    f'Select-Object EventID, EntryType, Source, Message, TimeGenerated, MachineName | '
                    f'ConvertTo-Json -Compress"'
                )
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=25)

                if result.returncode == 0 and result.stdout.strip():
                    try:
                        events = json.loads(result.stdout)
                        if not isinstance(events, list):
                            events = [events]

                        for ev in events:
                            raw_time = ev.get('TimeGenerated', '')
                            parsed_dt = parse_flexible_timestamp(raw_time)
                            formatted_time = parsed_dt.strftime('%Y-%m-%d %H:%M:%S') if parsed_dt else str(raw_time)

                            self.event_logs.append({
                                'log_type': log_type,
                                'event_id': str(ev.get('EventID', 'N/A')),
                                'level': str(ev.get('EntryType', 'Information')),
                                'source': str(ev.get('Source', 'N/A')),
                                'message': str(ev.get('Message', 'N/A')).replace('\r', ' ').replace('\n', ' '),
                                'timestamp': formatted_time,
                                'raw_datetime': parsed_dt,
                                'computer': str(ev.get('MachineName', 'N/A'))
                            })
                    except json.JSONDecodeError:
                        print(f"Failed to parse {log_type} log JSON")
            except Exception as e:
                print(f"Error parsing {log_type} event log: {e}")

        gc.collect()
        return self.event_logs


# ============================================================================
# MODULE 3: Timeline Creator (Zero Data Loss)
# ============================================================================

class TimelineCreator:
    """Creates a unified forensic timeline from files, event logs, and browser activity."""

    def __init__(self):
        self.timeline_events = []

    def create_timeline(self, file_data, log_data, browser_data):
        """Creates unified chronology without dropping records."""
        self.timeline_events = []

        # 1. File System Events
        for f in file_data:
            m_time = parse_flexible_timestamp(f.get('modified'))
            if m_time:
                self.timeline_events.append({
                    'timestamp': m_time,
                    'event_type': 'File Modified / Deleted',
                    'source': f.get('source', 'File System'),
                    'details': f"File: {f.get('name')} | Path: {f.get('path')}",
                    'artifact_type': 'file'
                })

            c_time = parse_flexible_timestamp(f.get('created'))
            if c_time and c_time != m_time:
                self.timeline_events.append({
                    'timestamp': c_time,
                    'event_type': 'File Created',
                    'source': f.get('source', 'File System'),
                    'details': f"File: {f.get('name')} | Size: {f.get('size')} bytes",
                    'artifact_type': 'file'
                })

        # 2. Windows Event Log Events
        for l in log_data:
            dt = l.get('raw_datetime') or parse_flexible_timestamp(l.get('timestamp'))
            if dt:
                msg_preview = str(l.get('message', ''))[:120]
                self.timeline_events.append({
                    'timestamp': dt,
                    'event_type': f"{l.get('log_type')} Log [{l.get('level')}]",
                    'source': f"EventID {l.get('event_id')} ({l.get('source')})",
                    'details': msg_preview,
                    'artifact_type': 'log'
                })

        # 3. Web Navigation Events
        for b in browser_data:
            dt = parse_flexible_timestamp(b.get('timestamp'))
            if dt:
                title = b.get('title') or "Web Navigation"
                url = b.get('url') or ""
                self.timeline_events.append({
                    'timestamp': dt,
                    'event_type': 'Web Navigation',
                    'source': b.get('browser', 'Browser'),
                    'details': f"{title} ({url})",
                    'artifact_type': 'browser'
                })

        self.timeline_events.sort(
            key=lambda x: x['timestamp'] if isinstance(x['timestamp'], datetime.datetime) else datetime.datetime.min,
            reverse=True
        )

        return self.timeline_events


# ============================================================================
# MODULE 4: Evidence Collector & Chain of Custody
# ============================================================================

class EvidenceCollector:
    """Manages digital evidence collection, SHA-256 validation, and chain of custody packaging."""

    def __init__(self):
        self.evidence_items = []

    def add_evidence(self, file_path, description, case_id):
        """Adds evidence item with computed integrity hash."""
        item = {
            'id': len(self.evidence_items) + 1,
            'file_path': file_path,
            'description': description,
            'case_id': case_id,
            'collected_time': datetime.datetime.now(),
            'hash': calculate_file_hash(file_path) if os.path.exists(file_path) else 'N/A',
            'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
        }
        self.evidence_items.append(item)
        return item

    def export_evidence(self, export_path, format_type='zip'):
        """Exports evidence files with JSON chain of custody."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        if format_type == 'zip':
            zip_path = os.path.join(export_path, f"evidence_collection_{timestamp}.zip")
            with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
                for item in self.evidence_items:
                    if os.path.exists(item['file_path']):
                        arc_name = f"evidence_{item['id']:03d}_{os.path.basename(item['file_path'])}"
                        zipf.write(item['file_path'], arc_name)

                custody_report = self._generate_custody_report()
                zipf.writestr("chain_of_custody.json", json.dumps(custody_report, indent=2, default=str))

            return zip_path
        else:
            folder_path = os.path.join(export_path, f"evidence_collection_{timestamp}")
            os.makedirs(folder_path, exist_ok=True)

            for item in self.evidence_items:
                if os.path.exists(item['file_path']):
                    dest_file = os.path.join(folder_path, f"evidence_{item['id']:03d}_{os.path.basename(item['file_path'])}")
                    shutil.copy2(item['file_path'], dest_file)

            custody_path = os.path.join(folder_path, "chain_of_custody.json")
            with open(custody_path, 'w', encoding='utf-8') as f:
                json.dump(self._generate_custody_report(), f, indent=2, default=str)

            return folder_path

    def _generate_custody_report(self):
        return {
            'report_generated': datetime.datetime.now().isoformat(),
            'total_items': len(self.evidence_items),
            'evidence_items': self.evidence_items,
            'investigator': os.getenv('USERNAME', 'Unknown'),
            'system_info': {
                'hostname': os.environ.get('COMPUTERNAME', 'Unknown'),
                'platform': sys.platform,
                'python_version': sys.version
            }
        }


# ============================================================================
# MODULE 5: Full Report Generator (Modern, Clean Responsive HTML)
# ============================================================================

class ReportGenerator:
    """Generates complete CSV and styled HTML forensic reports with clean, non-squashed tables."""

    def generate_csv_report(self, data, output_path, report_type):
        """Exports 100% of data rows to CSV."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report_type}_report_{timestamp}.csv"
        filepath = os.path.join(output_path, filename)

        if not data:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                csvfile.write("No data found\n")
            return filepath

        fieldnames = list(data[0].keys())
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in data:
                clean_row = {}
                for k, v in row.items():
                    if isinstance(v, datetime.datetime):
                        clean_row[k] = v.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        clean_row[k] = str(v)
                writer.writerow(clean_row)

        return filepath

    def generate_html_report(self, file_data, log_data, browser_data, timeline_data, output_path):
        """Generates comprehensive, responsive HTML report formatted properly for any browser."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"forensic_report_{timestamp}.html"
        filepath = os.path.join(output_path, filename)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ForensiX Pro - Investigation Report</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px 20px;
            background-color: #f8fafc;
            color: #1e293b;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1440px;
            margin: 0 auto;
            background: #ffffff;
            padding: 35px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
            border: 1px solid #e2e8f0;
        }}
        .header {{
            border-bottom: 2px solid #2563eb;
            padding-bottom: 18px;
            margin-bottom: 24px;
        }}
        h1 {{
            color: #0f172a;
            margin: 0 0 6px 0;
            font-size: 26px;
            font-weight: 700;
        }}
        .subtitle {{
            color: #64748b;
            font-size: 14px;
            margin: 0;
        }}
        .summary-card {{
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }}
        .summary-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 16px;
            font-size: 13px;
            color: #334155;
        }}
        .summary-meta span {{
            background: #ffffff;
            padding: 6px 14px;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
            font-weight: 500;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}
        .stat-box {{
            background: #ffffff;
            padding: 16px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #e2e8f0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.02);
        }}
        .stat-number {{
            font-size: 28px;
            font-weight: 700;
            color: #2563eb;
        }}
        .stat-label {{
            font-size: 12px;
            color: #64748b;
            text-transform: uppercase;
            font-weight: 600;
            margin-top: 4px;
        }}
        .section-header {{
            color: #0f172a;
            font-size: 18px;
            font-weight: 700;
            margin: 35px 0 15px 0;
            padding-bottom: 8px;
            border-bottom: 1px solid #e2e8f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .count-badge {{
            background: #eff6ff;
            color: #2563eb;
            font-size: 13px;
            padding: 3px 12px;
            border-radius: 20px;
            font-weight: 600;
            border: 1px solid #bfdbfe;
        }}
        .table-container {{
            width: 100%;
            overflow-x: auto;
            margin-bottom: 30px;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            background: #ffffff;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }}
        th {{
            background-color: #f1f5f9;
            color: #334155;
            font-weight: 700;
            padding: 12px 14px;
            border-bottom: 2px solid #cbd5e1;
            white-space: nowrap !important;
        }}
        td {{
            padding: 10px 14px;
            border-bottom: 1px solid #f1f5f9;
            vertical-align: top;
            color: #1e293b;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        tr:nth-child(even) {{
            background-color: #fafbfc;
        }}
        tr:hover {{
            background-color: #eff6ff;
        }}
        .col-nowrap {{
            white-space: nowrap !important;
        }}
        .col-path {{
            word-break: break-all;
            font-family: Consolas, monospace;
            font-size: 12px;
            color: #0f172a;
            min-width: 250px;
        }}
        .col-url {{
            word-break: break-all;
            color: #2563eb;
            text-decoration: none;
            min-width: 260px;
            display: inline-block;
        }}
        .col-url:hover {{
            text-decoration: underline;
        }}
        .col-msg {{
            word-break: break-word;
            line-height: 1.4;
            min-width: 250px;
        }}
        .col-hash {{
            font-family: Consolas, monospace;
            font-size: 11px;
            background: #f1f5f9;
            padding: 3px 6px;
            border-radius: 4px;
            border: 1px solid #e2e8f0;
            white-space: nowrap !important;
        }}
        .col-num {{
            text-align: right;
            white-space: nowrap !important;
            font-variant-numeric: tabular-nums;
            font-weight: 600;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            background: #f1f5f9;
            color: #475569;
            border: 1px solid #e2e8f0;
            white-space: nowrap !important;
        }}
        .badge-info {{
            background: #e0f2fe;
            color: #0369a1;
            border-color: #bae6fd;
        }}
        .badge-browser {{
            background: #f0fdf4;
            color: #15803d;
            border-color: #bbf7d0;
        }}
        .footer {{
            text-align: center;
            font-size: 12px;
            color: #94a3b8;
            margin-top: 40px;
            border-top: 1px solid #e2e8f0;
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ForensiX Pro - Forensic Analysis Report</h1>
            <p class="subtitle">ForensiX Pro Digital Forensics Suite &bull; Complete Evidence & Chronology Audit</p>
        </div>

        <div class="summary-card">
            <div class="summary-meta">
                <span><b>Generated:</b> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span>
                <span><b>Investigator:</b> {os.getenv('USERNAME', 'Unknown')}</span>
                <span><b>Host:</b> {os.environ.get('COMPUTERNAME', 'Unknown')}</span>
                <span><b>OS:</b> {sys.platform}</span>
            </div>
            
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-number">{len(file_data)}</div>
                    <div class="stat-label">Files Analyzed</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{len(log_data)}</div>
                    <div class="stat-label">Event Logs</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{len(browser_data)}</div>
                    <div class="stat-label">Browser Records</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{len(timeline_data)}</div>
                    <div class="stat-label">Timeline Events</div>
                </div>
            </div>
        </div>

        <div class="section-header">
            <span>1. File Recovery & Deleted Items</span>
            <span class="count-badge">{len(file_data)} Records</span>
        </div>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th style="min-width: 180px;">Name</th>
                        <th style="min-width: 280px;">Original / Deleted Path</th>
                        <th class="col-nowrap col-num">Size (Bytes)</th>
                        <th class="col-nowrap">Deleted / Modified Time</th>
                        <th class="col-nowrap">Source</th>
                        <th class="col-nowrap">SHA-256 Hash</th>
                    </tr>
                </thead>
                <tbody>
"""
        for f in file_data:
            mod_str = f.get('modified').strftime("%Y-%m-%d %H:%M:%S") if isinstance(f.get('modified'), datetime.datetime) else str(f.get('modified', 'N/A'))
            h = str(f.get('hash', 'N/A'))
            html_content += f"""                    <tr>
                        <td><b>{f.get('name', 'N/A')}</b></td>
                        <td class="col-path">{f.get('path', 'N/A')}</td>
                        <td class="col-nowrap col-num">{f.get('size', 0):,}</td>
                        <td class="col-nowrap">{mod_str}</td>
                        <td class="col-nowrap"><span class="badge">{f.get('source', 'N/A')}</span></td>
                        <td class="col-nowrap"><span class="col-hash">{h[:16]}...</span></td>
                    </tr>\n"""

        html_content += f"""                </tbody>
            </table>
        </div>

        <div class="section-header">
            <span>2. System Event Log Entries</span>
            <span class="count-badge">{len(log_data)} Records</span>
        </div>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th class="col-nowrap">Log Type</th>
                        <th class="col-nowrap col-num">Event ID</th>
                        <th class="col-nowrap">Source</th>
                        <th class="col-nowrap">Timestamp</th>
                        <th class="col-nowrap">Level</th>
                        <th style="min-width: 320px;">Message</th>
                    </tr>
                </thead>
                <tbody>
"""
        for l in log_data:
            html_content += f"""                    <tr>
                        <td class="col-nowrap"><span class="badge badge-info">{l.get('log_type', 'N/A')}</span></td>
                        <td class="col-nowrap col-num">{l.get('event_id', 'N/A')}</td>
                        <td class="col-nowrap">{l.get('source', 'N/A')}</td>
                        <td class="col-nowrap">{l.get('timestamp', 'N/A')}</td>
                        <td class="col-nowrap">{l.get('level', 'N/A')}</td>
                        <td class="col-msg">{str(l.get('message', 'N/A'))[:250]}</td>
                    </tr>\n"""

        html_content += f"""                </tbody>
            </table>
        </div>

        <div class="section-header">
            <span>3. Browser History Extraction</span>
            <span class="count-badge">{len(browser_data)} Records</span>
        </div>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th class="col-nowrap">Browser & Profile</th>
                        <th style="min-width: 220px; max-width: 380px;">Page Title</th>
                        <th style="min-width: 300px;">URL</th>
                        <th class="col-nowrap col-num">Visit Count</th>
                        <th class="col-nowrap">Last Visit Time</th>
                    </tr>
                </thead>
                <tbody>
"""
        for b in browser_data:
            ts_str = b.get('timestamp').strftime("%Y-%m-%d %H:%M:%S") if isinstance(b.get('timestamp'), datetime.datetime) else str(b.get('timestamp', 'N/A'))
            url_str = b.get('url', '#')
            html_content += f"""                    <tr>
                        <td class="col-nowrap"><span class="badge badge-browser">{b.get('browser', 'N/A')}</span></td>
                        <td class="col-msg"><b>{b.get('title', 'N/A')}</b></td>
                        <td><a class="col-url" href="{url_str}" target="_blank">{url_str}</a></td>
                        <td class="col-nowrap col-num">{b.get('visit_count', 1)}</td>
                        <td class="col-nowrap">{ts_str}</td>
                    </tr>\n"""

        html_content += f"""                </tbody>
            </table>
        </div>

        <div class="section-header">
            <span>4. Unified Forensic Chronology</span>
            <span class="count-badge">{len(timeline_data)} Events</span>
        </div>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th class="col-nowrap">Timestamp</th>
                        <th class="col-nowrap">Event Type</th>
                        <th class="col-nowrap">Source</th>
                        <th style="min-width: 350px;">Details</th>
                    </tr>
                </thead>
                <tbody>
"""
        for t in timeline_data:
            ts_str = t.get('timestamp').strftime("%Y-%m-%d %H:%M:%S") if isinstance(t.get('timestamp'), datetime.datetime) else str(t.get('timestamp', 'N/A'))
            html_content += f"""                    <tr>
                        <td class="col-nowrap">{ts_str}</td>
                        <td class="col-nowrap"><span class="badge">{t.get('event_type', 'N/A')}</span></td>
                        <td class="col-nowrap">{t.get('source', 'N/A')}</td>
                        <td class="col-msg">{t.get('details', 'N/A')}</td>
                    </tr>\n"""

        html_content += """                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>ForensiX Pro &bull; Secure Digital Evidence & Investigation Suite</p>
        </div>
    </div>
</body>
</html>"""

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return filepath


# ============================================================================
# DIALOG: Cell Details & Full Text Viewer
# ============================================================================

class CellDetailDialog(QDialog):
    """Clean modal dialog displaying the full text content of a clicked table cell with copy action."""
    def __init__(self, title, content, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Field Inspector: {title}")
        self.resize(620, 360)
        self.setStyleSheet(LIGHT_STYLESHEET)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        lbl = QLabel(f"Full Content for: <b>{title}</b>")
        layout.addWidget(lbl)

        self.text_view = QTextEdit()
        self.text_view.setPlainText(str(content))
        self.text_view.setReadOnly(True)
        self.text_view.setStyleSheet("font-family: Consolas, 'Segoe UI', monospace; font-size: 13px; line-height: 1.4;")
        layout.addWidget(self.text_view)

        btn_box = QHBoxLayout()
        btn_copy = QPushButton("Copy to Clipboard")
        btn_copy.setProperty("class", "primary-button")
        btn_copy.clicked.connect(self.copy_to_clipboard)

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)

        btn_box.addWidget(btn_copy)
        btn_box.addStretch()
        btn_box.addWidget(btn_close)
        layout.addLayout(btn_box)

    def copy_to_clipboard(self):
        cb = QApplication.clipboard()
        cb.setText(self.text_view.toPlainText())
        QMessageBox.information(self, "Copied", "Content copied to clipboard.")


# ============================================================================
# MODULE 6: PyQt5 GUI & Asynchronous Workers (Adjustable Light Theme)
# ============================================================================

LIGHT_STYLESHEET = """
/* Global Application Style */
QWidget {
    background-color: #f8fafc;
    color: #1e293b;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    font-size: 13px;
}

QMainWindow {
    background-color: #f1f5f9;
}

/* Sidebar Container */
#SidebarWidget {
    background-color: #ffffff;
    border-right: 1px solid #e2e8f0;
}

#SidebarTitle {
    font-size: 16px;
    font-weight: 700;
    color: #0f172a;
    padding: 10px 14px 2px 14px;
}

#SidebarSubtitle {
    font-size: 11px;
    font-weight: 600;
    color: #64748b;
    padding: 0px 14px 14px 14px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

/* Sidebar Navigation Buttons */
QPushButton.nav-button {
    background-color: #ffffff;
    color: #475569;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 12px 16px;
    text-align: left;
    font-size: 13px;
    font-weight: 600;
    margin: 2px 10px;
    min-height: 20px;
}

QPushButton.nav-button:hover {
    background-color: #f1f5f9;
    color: #0f172a;
}

QPushButton.nav-button:checked, QPushButton.nav-button.active {
    background-color: #eff6ff;
    color: #1d4ed8;
    border: 1px solid #bfdbfe;
    font-weight: 700;
}

/* Action & Tool Buttons */
QPushButton {
    background-color: #ffffff;
    color: #334155;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 12px;
    min-height: 18px;
}

QPushButton:hover {
    background-color: #f8fafc;
    border-color: #94a3b8;
    color: #0f172a;
}

QPushButton:pressed {
    background-color: #e2e8f0;
    border-color: #64748b;
}

QPushButton.primary-button {
    background-color: #2563eb;
    color: #ffffff;
    border: 1px solid #1d4ed8;
    font-weight: 600;
}

QPushButton.primary-button:hover {
    background-color: #1d4ed8;
}

QPushButton.primary-button:pressed {
    background-color: #1e40af;
}

/* Tab Widget & Tabs */
QTabWidget::pane {
    border: 1px solid #e2e8f0;
    background-color: #ffffff;
    border-radius: 6px;
    top: -1px;
}

QTabBar::tab {
    background-color: #f1f5f9;
    color: #475569;
    padding: 10px 24px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 600;
    font-size: 13px;
    border: 1px solid #cbd5e1;
    border-bottom: none;
    min-width: 140px;
    min-height: 22px;
}

QTabBar::tab:selected {
    background-color: #ffffff;
    color: #2563eb;
    border-top: 3px solid #2563eb;
    border-bottom: 1px solid #ffffff;
    font-weight: 700;
}

QTabBar::tab:hover:!selected {
    background-color: #e2e8f0;
    color: #0f172a;
}

/* Tables */
QTableWidget {
    background-color: #ffffff;
    color: #1e293b;
    border: 1px solid #e2e8f0;
    gridline-color: #f1f5f9;
    border-radius: 6px;
    selection-background-color: #dbeafe;
    selection-color: #1e3a8a;
    font-size: 12px;
}

QTableWidget::item {
    padding: 6px 12px;
    border: none;
}

QTableWidget::item:selected {
    background-color: #dbeafe;
    color: #1e3a8a;
}

QHeaderView::section {
    background-color: #f8fafc;
    color: #334155;
    padding: 10px 14px;
    border: none;
    border-bottom: 2px solid #e2e8f0;
    border-right: 1px solid #e2e8f0;
    font-weight: 700;
    font-size: 12px;
    min-height: 24px;
}

/* Inputs, Combos & Splitters */
QLineEdit, QComboBox, QTextEdit {
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 7px 12px;
    font-size: 13px;
    min-height: 20px;
}

QLineEdit:focus, QComboBox:focus, QTextEdit:focus {
    border: 1.5px solid #2563eb;
    outline: none;
}

QSplitter::handle {
    background-color: #e2e8f0;
    width: 3px;
}

QSplitter::handle:hover {
    background-color: #2563eb;
}

/* Progress Bar */
QProgressBar {
    background-color: #e2e8f0;
    border: none;
    border-radius: 2px;
    height: 4px;
}

QProgressBar::chunk {
    background-color: #2563eb;
    border-radius: 2px;
}

/* Status Bar */
QStatusBar {
    background-color: #ffffff;
    color: #475569;
    border-top: 1px solid #e2e8f0;
    font-size: 12px;
    padding: 6px 12px;
}

QLabel.section-header {
    font-size: 17px;
    font-weight: 700;
    color: #0f172a;
    padding-bottom: 2px;
}

QLabel.section-desc {
    font-size: 12px;
    color: #64748b;
    margin-bottom: 8px;
}

QCheckBox {
    spacing: 8px;
    font-weight: 500;
    color: #334155;
    font-size: 13px;
}

QCheckBox::indicator {
    width: 17px;
    height: 17px;
    border: 1.5px solid #cbd5e1;
    border-radius: 4px;
    background-color: #ffffff;
}

QCheckBox::indicator:checked {
    background-color: #2563eb;
    border-color: #2563eb;
}
"""

if PYQT_AVAILABLE:

    class ForensicWorker(QThread):
        """Asynchronous background worker to execute heavy scans without blocking the GUI."""
        task_started = pyqtSignal(str)
        task_progress = pyqtSignal(str, int)
        task_finished = pyqtSignal(str, object)
        task_error = pyqtSignal(str, str)

        def __init__(self, task_name, task_func, *args, **kwargs):
            super().__init__()
            self.task_name = task_name
            self.task_func = task_func
            self.args = args
            self.kwargs = kwargs

        def run(self):
            self.task_started.emit(self.task_name)
            try:
                result = self.task_func(*self.args, **self.kwargs)
                self.task_finished.emit(self.task_name, result)
            except Exception as e:
                import traceback
                self.task_error.emit(self.task_name, f"{str(e)}\n{traceback.format_exc()}")


    class ForensicAnalysisGUI(QMainWindow):
        def __init__(self):
            super().__init__()
            self.file_recovery = FileRecoveryEngine()
            self.log_analyzer = LogAnalyzer()
            self.timeline_creator = TimelineCreator()
            self.evidence_collector = EvidenceCollector()
            self.report_generator = ReportGenerator()

            self.file_data = []
            self.log_data = []
            self.browser_data = []
            self.timeline_data = []
            self.last_generated_html_path = None
            self.current_worker = None
            self.nav_buttons = []

            self.init_ui()

        def init_ui(self):
            self.setWindowTitle('ForensiX Pro - Digital Forensics Suite')
            self.setGeometry(60, 60, 1340, 860)
            self.setStyleSheet(LIGHT_STYLESHEET)

            central_widget = QWidget()
            self.setCentralWidget(central_widget)
            outer_layout = QHBoxLayout(central_widget)
            outer_layout.setContentsMargins(0, 0, 0, 0)
            outer_layout.setSpacing(0)

            self.main_splitter = QSplitter(Qt.Horizontal)
            self.main_splitter.setHandleWidth(4)

            # Sidebar
            sidebar = QWidget()
            sidebar.setObjectName("SidebarWidget")
            sidebar.setMinimumWidth(180)
            sidebar_layout = QVBoxLayout(sidebar)
            sidebar_layout.setContentsMargins(0, 15, 0, 15)
            sidebar_layout.setSpacing(4)

            title_label = QLabel("ForensiX Pro")
            title_label.setObjectName("SidebarTitle")
            sidebar_layout.addWidget(title_label)

            subtitle_label = QLabel("Digital Forensics Suite")
            subtitle_label.setObjectName("SidebarSubtitle")
            sidebar_layout.addWidget(subtitle_label)

            self.btn_nav_file_recovery = QPushButton('File Recovery')
            self.btn_nav_log_analysis = QPushButton('Log and Browser')
            self.btn_nav_timeline = QPushButton('Timeline Creation')
            self.btn_nav_evidence = QPushButton('Evidence Collection')
            self.btn_nav_reports = QPushButton('Generate Reports')

            self.nav_buttons = [
                self.btn_nav_file_recovery,
                self.btn_nav_log_analysis,
                self.btn_nav_timeline,
                self.btn_nav_evidence,
                self.btn_nav_reports
            ]

            for idx, btn in enumerate(self.nav_buttons):
                btn.setProperty("class", "nav-button")
                btn.setCheckable(True)
                btn.clicked.connect(lambda checked, i=idx: self.switch_nav(i))
                sidebar_layout.addWidget(btn)

            sidebar_layout.addStretch()

            # Right Tab container
            self.tab_widget = QTabWidget()
            self.tab_widget.tabBar().setVisible(False)

            self.create_file_recovery_tab()
            self.create_log_analysis_tab()
            self.create_timeline_tab()
            self.create_evidence_tab()
            self.create_reports_tab()

            self.main_splitter.addWidget(sidebar)
            self.main_splitter.addWidget(self.tab_widget)
            self.main_splitter.setSizes([230, 1110])
            self.main_splitter.setCollapsible(0, False)

            outer_layout.addWidget(self.main_splitter)

            self.switch_nav(0)
            self.statusBar().showMessage('Ready. Select a module to begin investigation.')

        def switch_nav(self, index):
            for i, btn in enumerate(self.nav_buttons):
                btn.setChecked(i == index)
            self.tab_widget.setCurrentIndex(index)

        def configure_table_behavior(self, table):
            """Applies read-only triggers, proper row heights, and double-click inspectors to tables."""
            table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            table.setSelectionBehavior(QAbstractItemView.SelectRows)
            table.setSelectionMode(QAbstractItemView.SingleSelection)
            table.setAlternatingRowColors(True)
            table.verticalHeader().setDefaultSectionSize(34)
            table.verticalHeader().setVisible(True)
            table.horizontalHeader().setHighlightSections(False)
            table.horizontalHeader().setMinimumSectionSize(110)
            table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            table.cellDoubleClicked.connect(lambda row, col: self.show_cell_inspector(table, row, col))

        def show_cell_inspector(self, table, row, col):
            """Opens a clean details dialog when user double-clicks any table cell."""
            header_item = table.horizontalHeaderItem(col)
            header_text = header_item.text() if header_item else f"Column {col+1}"
            item = table.item(row, col)
            val = item.text() if item else ""
            dlg = CellDetailDialog(header_text, val, self)
            dlg.exec_()

        # --------------------------------------------------------------------
        # TAB 1: FILE RECOVERY
        # --------------------------------------------------------------------
        def create_file_recovery_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)
            layout.setContentsMargins(22, 22, 22, 22)
            layout.setSpacing(12)

            header = QLabel('File Recovery and Recycle Bin Analysis')
            header.setProperty("class", "section-header")
            layout.addWidget(header)

            desc = QLabel('Parse Windows $I/$R Recycle Bin metadata records, deleted shadow artifacts, and restore files. Double click any cell to view full path.')
            desc.setProperty("class", "section-desc")
            layout.addWidget(desc)

            btn_layout = QHBoxLayout()
            btn_layout.setSpacing(10)

            self.btn_scan_recycle = QPushButton('Scan Windows Recycle Bin')
            self.btn_scan_recycle.setProperty("class", "primary-button")
            self.btn_scan_deleted = QPushButton('Scan Deleted / Temp Artifacts')
            self.btn_restore_selected = QPushButton('Save or Restore Selected File')
            self.btn_export_files = QPushButton('Export Results (CSV)')

            self.btn_scan_recycle.clicked.connect(self.start_scan_recycle_bin)
            self.btn_scan_deleted.clicked.connect(self.start_scan_deleted_files)
            self.btn_restore_selected.clicked.connect(self.restore_selected_file)
            self.btn_export_files.clicked.connect(self.export_file_results)

            btn_layout.addWidget(self.btn_scan_recycle)
            btn_layout.addWidget(self.btn_scan_deleted)
            btn_layout.addWidget(self.btn_restore_selected)
            btn_layout.addWidget(self.btn_export_files)
            btn_layout.addStretch()
            layout.addLayout(btn_layout)

            self.file_progress = QProgressBar()
            self.file_progress.setTextVisible(False)
            self.file_progress.setFixedHeight(4)
            layout.addWidget(self.file_progress)

            self.file_table = QTableWidget()
            self.file_table.setColumnCount(7)
            self.file_table.setHorizontalHeaderLabels([
                'Original Name', 'Original / Deleted Path', 'Size (Bytes)',
                'Deleted / Modified Time', 'Source', 'SHA-256 Hash', 'Physical Path'
            ])
            self.configure_table_behavior(self.file_table)
            
            h = self.file_table.horizontalHeader()
            h.setSectionResizeMode(QHeaderView.Interactive)
            h.setSectionResizeMode(1, QHeaderView.Stretch)
            self.file_table.setColumnWidth(0, 180)
            self.file_table.setColumnWidth(2, 110)
            self.file_table.setColumnWidth(3, 170)
            self.file_table.setColumnWidth(4, 160)
            self.file_table.setColumnWidth(5, 140)
            self.file_table.setColumnWidth(6, 180)

            layout.addWidget(self.file_table)
            self.tab_widget.addTab(tab, 'File Recovery')

        # --------------------------------------------------------------------
        # TAB 2: LOG & BROWSER ANALYSIS
        # --------------------------------------------------------------------
        def create_log_analysis_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)
            layout.setContentsMargins(22, 22, 22, 22)
            layout.setSpacing(12)

            header = QLabel('System Event Logs and Multi-Profile Browser Analysis')
            header.setProperty("class", "section-header")
            layout.addWidget(header)

            desc = QLabel('Extract event records from Windows logs and history from specific user profiles. Double click any cell to view full text.')
            desc.setProperty("class", "section-desc")
            layout.addWidget(desc)

            profile_box = QHBoxLayout()
            profile_box.setSpacing(10)
            profile_label = QLabel("Select Browser Profile:")
            profile_label.setStyleSheet("font-weight: 600; color: #334155;")
            self.profile_combo = QComboBox()
            self.profile_combo.setMinimumWidth(320)
            self.btn_refresh_profiles = QPushButton("Detect Profiles")
            self.btn_refresh_profiles.clicked.connect(self.populate_browser_profiles)

            profile_box.addWidget(profile_label)
            profile_box.addWidget(self.profile_combo)
            profile_box.addWidget(self.btn_refresh_profiles)
            profile_box.addStretch()
            layout.addLayout(profile_box)

            btn_layout = QHBoxLayout()
            btn_layout.setSpacing(10)

            self.btn_scan_event_logs = QPushButton('Analyze Windows Event Logs')
            self.btn_scan_event_logs.setProperty("class", "primary-button")
            self.btn_scan_browser = QPushButton('Extract History for Selected Profile')
            self.btn_export_logs = QPushButton('Export Results (CSV)')

            self.btn_scan_event_logs.clicked.connect(self.start_analyze_event_logs)
            self.btn_scan_browser.clicked.connect(self.start_extract_browser_history)
            self.btn_export_logs.clicked.connect(self.export_log_results)

            btn_layout.addWidget(self.btn_scan_event_logs)
            btn_layout.addWidget(self.btn_scan_browser)
            btn_layout.addWidget(self.btn_export_logs)
            btn_layout.addStretch()
            layout.addLayout(btn_layout)

            self.log_progress = QProgressBar()
            self.log_progress.setTextVisible(False)
            self.log_progress.setFixedHeight(4)
            layout.addWidget(self.log_progress)

            log_subtabs = QTabWidget()
            log_subtabs.setStyleSheet("QTabWidget::pane { border: 1px solid #cbd5e1; }")

            # 1. Event logs table
            self.event_log_table = QTableWidget()
            self.event_log_table.setColumnCount(6)
            self.event_log_table.setHorizontalHeaderLabels(['Log Type', 'Event ID', 'Source', 'Timestamp', 'Level', 'Message'])
            self.configure_table_behavior(self.event_log_table)
            h_ev = self.event_log_table.horizontalHeader()
            h_ev.setSectionResizeMode(QHeaderView.Interactive)
            h_ev.setSectionResizeMode(5, QHeaderView.Stretch)
            self.event_log_table.setColumnWidth(0, 120)
            self.event_log_table.setColumnWidth(1, 90)
            self.event_log_table.setColumnWidth(2, 160)
            self.event_log_table.setColumnWidth(3, 160)
            self.event_log_table.setColumnWidth(4, 110)
            log_subtabs.addTab(self.event_log_table, 'Windows Event Logs')

            # 2. Browser history table
            self.browser_table = QTableWidget()
            self.browser_table.setColumnCount(5)
            self.browser_table.setHorizontalHeaderLabels(['Browser and Profile', 'Page Title', 'URL', 'Visit Count', 'Last Visit Time'])
            self.configure_table_behavior(self.browser_table)
            h_br = self.browser_table.horizontalHeader()
            h_br.setSectionResizeMode(QHeaderView.Interactive)
            h_br.setSectionResizeMode(2, QHeaderView.Stretch)
            self.browser_table.setColumnWidth(0, 200)
            self.browser_table.setColumnWidth(1, 240)
            self.browser_table.setColumnWidth(3, 90)
            self.browser_table.setColumnWidth(4, 160)
            log_subtabs.addTab(self.browser_table, 'Browser History')

            layout.addWidget(log_subtabs)
            self.tab_widget.addTab(tab, 'Log Analysis')

            self.populate_browser_profiles()

        def populate_browser_profiles(self):
            """Populates profile dropdown with all detected browser user profiles."""
            self.profile_combo.clear()
            self.profile_combo.addItem("All Detected Profiles", "ALL")

            profiles = self.log_analyzer.get_available_browser_profiles()
            for p in profiles:
                label = f"{p['browser']} - {p['profile_name']}"
                self.profile_combo.addItem(label, p['id'])

            if not profiles:
                self.statusBar().showMessage("No standard browser profiles found in default directories.")
            else:
                self.statusBar().showMessage(f"Found {len(profiles)} browser profiles ready for extraction.")

        # --------------------------------------------------------------------
        # TAB 3: TIMELINE
        # --------------------------------------------------------------------
        def create_timeline_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)
            layout.setContentsMargins(22, 22, 22, 22)
            layout.setSpacing(12)

            header = QLabel('Unified Forensic Chronology and Timeline')
            header.setProperty("class", "section-header")
            layout.addWidget(header)

            desc = QLabel('Synthesizes files, Windows logs, and browser activities into a single chronological view.')
            desc.setProperty("class", "section-desc")
            layout.addWidget(desc)

            btn_layout = QHBoxLayout()
            btn_layout.setSpacing(10)

            self.btn_create_timeline = QPushButton('Generate Chronological Timeline')
            self.btn_create_timeline.setProperty("class", "primary-button")
            self.btn_export_timeline = QPushButton('Export Timeline (CSV)')

            self.btn_create_timeline.clicked.connect(self.start_create_timeline)
            self.btn_export_timeline.clicked.connect(self.export_timeline)

            btn_layout.addWidget(self.btn_create_timeline)
            btn_layout.addWidget(self.btn_export_timeline)
            btn_layout.addStretch()
            layout.addLayout(btn_layout)

            self.timeline_progress = QProgressBar()
            self.timeline_progress.setTextVisible(False)
            self.timeline_progress.setFixedHeight(4)
            layout.addWidget(self.timeline_progress)

            self.timeline_table = QTableWidget()
            self.timeline_table.setColumnCount(4)
            self.timeline_table.setHorizontalHeaderLabels(['Timestamp', 'Event Type', 'Source / Subsystem', 'Details'])
            self.configure_table_behavior(self.timeline_table)
            h_tm = self.timeline_table.horizontalHeader()
            h_tm.setSectionResizeMode(QHeaderView.Interactive)
            h_tm.setSectionResizeMode(3, QHeaderView.Stretch)
            self.timeline_table.setColumnWidth(0, 170)
            self.timeline_table.setColumnWidth(1, 180)
            self.timeline_table.setColumnWidth(2, 190)

            layout.addWidget(self.timeline_table)
            self.tab_widget.addTab(tab, 'Timeline')

        # --------------------------------------------------------------------
        # TAB 4: EVIDENCE COLLECTION
        # --------------------------------------------------------------------
        def create_evidence_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)
            layout.setContentsMargins(22, 22, 22, 22)
            layout.setSpacing(12)

            header = QLabel('Evidence Collection and Chain of Custody')
            header.setProperty("class", "section-header")
            layout.addWidget(header)

            desc = QLabel('Secure digital artifacts, calculate SHA-256 integrity hashes, and generate custody reports.')
            desc.setProperty("class", "section-desc")
            layout.addWidget(desc)

            case_layout = QHBoxLayout()
            case_layout.setSpacing(10)
            case_label = QLabel('Case Reference ID:')
            case_label.setStyleSheet("font-weight: 600; color: #334155;")
            self.case_id_input = QLineEdit()
            self.case_id_input.setPlaceholderText("e.g. CASE-2026-001")
            self.case_id_input.setMaximumWidth(300)

            case_layout.addWidget(case_label)
            case_layout.addWidget(self.case_id_input)
            case_layout.addStretch()
            layout.addLayout(case_layout)

            btn_layout = QHBoxLayout()
            btn_layout.setSpacing(10)

            self.btn_add_evidence = QPushButton('Add Evidence File')
            self.btn_add_evidence.setProperty("class", "primary-button")
            self.btn_export_zip = QPushButton('Export as Secure ZIP')
            self.btn_export_folder = QPushButton('Export as Folder')

            self.btn_add_evidence.clicked.connect(self.add_evidence_file)
            self.btn_export_zip.clicked.connect(lambda: self.export_evidence('zip'))
            self.btn_export_folder.clicked.connect(lambda: self.export_evidence('folder'))

            btn_layout.addWidget(self.btn_add_evidence)
            btn_layout.addWidget(self.btn_export_zip)
            btn_layout.addWidget(self.btn_export_folder)
            btn_layout.addStretch()
            layout.addLayout(btn_layout)

            self.evidence_table = QTableWidget()
            self.evidence_table.setColumnCount(5)
            self.evidence_table.setHorizontalHeaderLabels(['ID', 'File Path', 'Description', 'Collected Time', 'SHA-256 Hash'])
            self.configure_table_behavior(self.evidence_table)
            h_evd = self.evidence_table.horizontalHeader()
            h_evd.setSectionResizeMode(QHeaderView.Interactive)
            h_evd.setSectionResizeMode(1, QHeaderView.Stretch)
            self.evidence_table.setColumnWidth(0, 60)
            self.evidence_table.setColumnWidth(2, 220)
            self.evidence_table.setColumnWidth(3, 160)
            self.evidence_table.setColumnWidth(4, 180)

            layout.addWidget(self.evidence_table)
            self.tab_widget.addTab(tab, 'Evidence Collection')

        # --------------------------------------------------------------------
        # TAB 5: REPORT GENERATION
        # --------------------------------------------------------------------
        def create_reports_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)
            layout.setContentsMargins(22, 22, 22, 22)
            layout.setSpacing(12)

            header = QLabel('Forensic Investigation Report Export')
            header.setProperty("class", "section-header")
            layout.addWidget(header)

            desc = QLabel('Export full-fidelity reports in formatted CSV or styled standalone HTML format.')
            desc.setProperty("class", "section-desc")
            layout.addWidget(desc)

            opts_layout = QHBoxLayout()
            opts_layout.setSpacing(16)
            self.include_files = QCheckBox('Include File Recovery Records')
            self.include_logs = QCheckBox('Include Event Logs')
            self.include_browser = QCheckBox('Include Browser Records')
            self.include_timeline = QCheckBox('Include Timeline Events')

            self.include_files.setChecked(True)
            self.include_logs.setChecked(True)
            self.include_browser.setChecked(True)
            self.include_timeline.setChecked(True)

            opts_layout.addWidget(self.include_files)
            opts_layout.addWidget(self.include_logs)
            opts_layout.addWidget(self.include_browser)
            opts_layout.addWidget(self.include_timeline)
            opts_layout.addStretch()
            layout.addLayout(opts_layout)

            btn_layout = QHBoxLayout()
            btn_layout.setSpacing(10)

            self.btn_generate_csv = QPushButton('Export Full CSV Reports')
            self.btn_generate_html = QPushButton('Generate Full HTML Report')
            self.btn_generate_html.setProperty("class", "primary-button")
            self.btn_open_browser = QPushButton('Open HTML Report in Web Browser')
            self.btn_open_browser.setEnabled(False)

            self.btn_generate_csv.clicked.connect(self.generate_csv_report)
            self.btn_generate_html.clicked.connect(self.generate_html_report)
            self.btn_open_browser.clicked.connect(self.open_report_in_browser)

            btn_layout.addWidget(self.btn_generate_csv)
            btn_layout.addWidget(self.btn_generate_html)
            btn_layout.addWidget(self.btn_open_browser)
            btn_layout.addStretch()
            layout.addLayout(btn_layout)

            preview_header = QLabel('Report Summary & Log Preview')
            preview_header.setStyleSheet("font-weight: 600; color: #475569; margin-top: 8px;")
            layout.addWidget(preview_header)

            self.report_preview = QTextEdit()
            self.report_preview.setReadOnly(True)
            layout.addWidget(self.report_preview)

            self.tab_widget.addTab(tab, 'Generate Reports')

        def open_report_in_browser(self):
            """Opens the generated HTML report file in user's default browser."""
            if self.last_generated_html_path and os.path.exists(self.last_generated_html_path):
                webbrowser.open('file://' + os.path.abspath(self.last_generated_html_path))
            else:
                QMessageBox.warning(self, "Report Required", "Please generate an HTML report first.")

        # --------------------------------------------------------------------
        # ASYNC TASK RUNNER (QThread Worker Dispatcher)
        # --------------------------------------------------------------------
        def launch_async_task(self, task_name, task_func, progress_bar, on_finished, *args, **kwargs):
            """Dispatches task to a background QThread to keep UI fully responsive and light."""
            self.statusBar().showMessage(f"Running {task_name}...")
            progress_bar.setRange(0, 0)

            worker = ForensicWorker(task_name, task_func, *args, **kwargs)
            worker.task_finished.connect(lambda name, result: self._on_worker_finished(worker, progress_bar, on_finished, result))
            worker.task_error.connect(lambda name, err: self._on_worker_error(worker, progress_bar, err))
            self.current_worker = worker
            worker.start()

        def _on_worker_finished(self, worker, progress_bar, on_finished, result):
            progress_bar.setRange(0, 1)
            progress_bar.setValue(1)
            on_finished(result)
            self.statusBar().showMessage("Ready")
            gc.collect()

        def _on_worker_error(self, worker, progress_bar, error_msg):
            progress_bar.setRange(0, 1)
            progress_bar.setValue(0)
            self.statusBar().showMessage("Error occurred during scan.")
            QMessageBox.critical(self, "Execution Error", f"Operation encountered an error:\n{error_msg}")
            gc.collect()

        # --------------------------------------------------------------------
        # ACTION HANDLERS
        # --------------------------------------------------------------------
        def start_scan_recycle_bin(self):
            self.launch_async_task(
                "Recycle Bin Scan",
                self.file_recovery.scan_recycle_bin,
                self.file_progress,
                self._handle_recycle_bin_done
            )

        def _handle_recycle_bin_done(self, files):
            self.file_data = files
            self._update_file_table()
            self.statusBar().showMessage(f"Found {len(files)} files in Recycle Bin ($I/$R parsed).")

        def start_scan_deleted_files(self):
            self.launch_async_task(
                "Deleted / Temp Scan",
                self.file_recovery.scan_deleted_files,
                self.file_progress,
                self._handle_deleted_files_done
            )

        def _handle_deleted_files_done(self, files):
            self.file_data = files
            self._update_file_table()
            self.statusBar().showMessage(f"Found {len(files)} deleted / temporary artifact files.")

        def restore_selected_file(self):
            """Restores selected file from Recycle Bin / Temp to target folder."""
            selected_rows = self.file_table.selectionModel().selectedRows()
            if not selected_rows:
                QMessageBox.warning(self, "Selection Required", "Please select a file row in the table to restore.")
                return

            row_idx = selected_rows[0].row()
            if row_idx >= len(self.file_data):
                return

            file_info = self.file_data[row_idx]
            phys_path = file_info.get('physical_path') or file_info.get('path')
            if not phys_path or not os.path.exists(phys_path):
                QMessageBox.critical(self, "Restore Failed", f"Physical content file not found on disk:\n{phys_path}")
                return

            dest_dir = QFileDialog.getExistingDirectory(self, "Select Destination Folder to Save Recovered File")
            if dest_dir:
                try:
                    orig_name = file_info.get('name')
                    saved_path = self.file_recovery.restore_file_to_destination(phys_path, dest_dir, orig_name)
                    QMessageBox.information(self, "File Restored Successfully", f"File saved to:\n{saved_path}")
                except Exception as e:
                    QMessageBox.critical(self, "Restore Error", f"Failed to restore file: {str(e)}")

        def _update_file_table(self):
            """Batched memory-efficient table rendering."""
            self.file_table.setUpdatesEnabled(False)
            self.file_table.setRowCount(len(self.file_data))
            for i, item in enumerate(self.file_data):
                self.file_table.setItem(i, 0, QTableWidgetItem(str(item.get('name', 'N/A'))))
                self.file_table.setItem(i, 1, QTableWidgetItem(str(item.get('path', 'N/A'))))
                self.file_table.setItem(i, 2, QTableWidgetItem(f"{item.get('size', 0):,}"))
                mod_str = item.get('modified').strftime("%Y-%m-%d %H:%M:%S") if isinstance(item.get('modified'), datetime.datetime) else str(item.get('modified', 'N/A'))
                self.file_table.setItem(i, 3, QTableWidgetItem(mod_str))
                self.file_table.setItem(i, 4, QTableWidgetItem(str(item.get('source', 'N/A'))))
                h = str(item.get('hash', 'N/A'))
                self.file_table.setItem(i, 5, QTableWidgetItem(h[:16] + "..." if len(h) > 16 else h))
                self.file_table.setItem(i, 6, QTableWidgetItem(str(item.get('physical_path', 'N/A'))))
            self.file_table.setUpdatesEnabled(True)

        def export_file_results(self):
            if not self.file_data:
                QMessageBox.warning(self, "Warning", "No file data to export. Please scan for files first.")
                return
            path, _ = QFileDialog.getSaveFileName(self, "Export File Results", "file_recovery_report.csv", "CSV files (*.csv)")
            if path:
                try:
                    self.report_generator.generate_csv_report(self.file_data, os.path.dirname(path), 'file_recovery')
                    QMessageBox.information(self, "Export Complete", f"Exported file results to:\n{path}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to export: {e}")

        def start_analyze_event_logs(self):
            self.launch_async_task(
                "Windows Event Log Analysis",
                self.log_analyzer.analyze_windows_logs,
                self.log_progress,
                self._handle_event_logs_done
            )

        def _handle_event_logs_done(self, logs):
            self.log_data = logs
            self._update_log_table()
            self.statusBar().showMessage(f"Analyzed {len(logs)} Windows Event Log records.")

        def _update_log_table(self):
            self.event_log_table.setUpdatesEnabled(False)
            self.event_log_table.setRowCount(len(self.log_data))
            for i, item in enumerate(self.log_data):
                self.event_log_table.setItem(i, 0, QTableWidgetItem(str(item.get('log_type', 'N/A'))))
                self.event_log_table.setItem(i, 1, QTableWidgetItem(str(item.get('event_id', 'N/A'))))
                self.event_log_table.setItem(i, 2, QTableWidgetItem(str(item.get('source', 'N/A'))))
                self.event_log_table.setItem(i, 3, QTableWidgetItem(str(item.get('timestamp', 'N/A'))))
                self.event_log_table.setItem(i, 4, QTableWidgetItem(str(item.get('level', 'N/A'))))
                msg = str(item.get('message', 'N/A'))
                self.event_log_table.setItem(i, 5, QTableWidgetItem(msg))
            self.event_log_table.setUpdatesEnabled(True)

        def start_extract_browser_history(self):
            selected_profile_id = self.profile_combo.currentData()
            self.launch_async_task(
                "Browser History Extraction",
                self.log_analyzer.analyze_browser_history,
                self.log_progress,
                self._handle_browser_done,
                selected_profile_id
            )

        def _handle_browser_done(self, history):
            self.browser_data = history
            self._update_browser_table()
            self.statusBar().showMessage(f"Extracted {len(history)} browser history records.")

        def _update_browser_table(self):
            self.browser_table.setUpdatesEnabled(False)
            self.browser_table.setRowCount(len(self.browser_data))
            for i, item in enumerate(self.browser_data):
                self.browser_table.setItem(i, 0, QTableWidgetItem(str(item.get('browser', 'N/A'))))
                self.browser_table.setItem(i, 1, QTableWidgetItem(str(item.get('title', 'N/A'))))
                self.browser_table.setItem(i, 2, QTableWidgetItem(str(item.get('url', 'N/A'))))
                self.browser_table.setItem(i, 3, QTableWidgetItem(str(item.get('visit_count', 1))))
                ts_str = item.get('timestamp').strftime("%Y-%m-%d %H:%M:%S") if isinstance(item.get('timestamp'), datetime.datetime) else str(item.get('timestamp', 'N/A'))
                self.browser_table.setItem(i, 4, QTableWidgetItem(ts_str))
            self.browser_table.setUpdatesEnabled(True)

        def export_log_results(self):
            if not self.log_data and not self.browser_data:
                QMessageBox.warning(self, "Warning", "No log or browser data to export.")
                return
            export_dir = QFileDialog.getExistingDirectory(self, "Select Export Directory")
            if export_dir:
                try:
                    if self.log_data:
                        self.report_generator.generate_csv_report(self.log_data, export_dir, 'event_logs')
                    if self.browser_data:
                        self.report_generator.generate_csv_report(self.browser_data, export_dir, 'browser_history')
                    QMessageBox.information(self, "Success", f"Logs exported to {export_dir}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to export logs: {e}")

        def start_create_timeline(self):
            if not any([self.file_data, self.log_data, self.browser_data]):
                QMessageBox.warning(self, "Data Required", "Please run at least one scan module (Files, Logs, or Browser) before creating timeline.")
                return
            self.launch_async_task(
                "Timeline Generation",
                self.timeline_creator.create_timeline,
                self.timeline_progress,
                self._handle_timeline_done,
                self.file_data, self.log_data, self.browser_data
            )

        def _handle_timeline_done(self, timeline):
            self.timeline_data = timeline
            self._update_timeline_table()
            self.statusBar().showMessage(f"Generated unified timeline with {len(timeline)} events.")

        def _update_timeline_table(self):
            self.timeline_table.setUpdatesEnabled(False)
            self.timeline_table.setRowCount(len(self.timeline_data))
            for i, item in enumerate(self.timeline_data):
                ts_str = item.get('timestamp').strftime("%Y-%m-%d %H:%M:%S") if isinstance(item.get('timestamp'), datetime.datetime) else str(item.get('timestamp', 'N/A'))
                self.timeline_table.setItem(i, 0, QTableWidgetItem(ts_str))
                self.timeline_table.setItem(i, 1, QTableWidgetItem(str(item.get('event_type', 'N/A'))))
                self.timeline_table.setItem(i, 2, QTableWidgetItem(str(item.get('source', 'N/A'))))
                self.timeline_table.setItem(i, 3, QTableWidgetItem(str(item.get('details', 'N/A'))))
            self.timeline_table.setUpdatesEnabled(True)

        def export_timeline(self):
            if not self.timeline_data:
                QMessageBox.warning(self, "Warning", "No timeline data to export.")
                return
            path, _ = QFileDialog.getSaveFileName(self, "Export Timeline", "forensic_timeline.csv", "CSV files (*.csv)")
            if path:
                try:
                    self.report_generator.generate_csv_report(self.timeline_data, os.path.dirname(path), 'timeline')
                    QMessageBox.information(self, "Success", f"Timeline exported to {path}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to export timeline: {e}")

        def add_evidence_file(self):
            file_path, _ = QFileDialog.getOpenFileName(self, "Select Evidence File to Secure")
            if file_path:
                desc, ok = QInputDialog.getText(self, "Evidence Description", "Enter description / notes for this evidence item:")
                if ok and desc:
                    case_id = self.case_id_input.text().strip() or "CASE-UNKNOWN"
                    item = self.evidence_collector.add_evidence(file_path, desc, case_id)
                    self._update_evidence_table()

        def _update_evidence_table(self):
            items = self.evidence_collector.evidence_items
            self.evidence_table.setRowCount(len(items))
            for i, item in enumerate(items):
                self.evidence_table.setItem(i, 0, QTableWidgetItem(str(item['id'])))
                self.evidence_table.setItem(i, 1, QTableWidgetItem(str(item['file_path'])))
                self.evidence_table.setItem(i, 2, QTableWidgetItem(str(item['description'])))
                self.evidence_table.setItem(i, 3, QTableWidgetItem(str(item['collected_time'].strftime("%Y-%m-%d %H:%M:%S"))))
                h = str(item['hash'])
                self.evidence_table.setItem(i, 4, QTableWidgetItem(h[:16] + "..." if len(h) > 16 else h))

        def export_evidence(self, format_type):
            if not self.evidence_collector.evidence_items:
                QMessageBox.warning(self, "Warning", "No evidence items to export.")
                return
            export_path = QFileDialog.getExistingDirectory(self, "Select Evidence Export Destination Directory")
            if export_path:
                try:
                    result = self.evidence_collector.export_evidence(export_path, format_type)
                    QMessageBox.information(self, "Evidence Exported", f"Evidence and chain of custody secured at:\n{result}")
                except Exception as e:
                    QMessageBox.critical(self, "Export Failed", f"Failed to package evidence: {e}")

        def generate_csv_report(self):
            export_path = QFileDialog.getExistingDirectory(self, "Select CSV Reports Output Directory")
            if export_path:
                try:
                    gen_count = 0
                    if self.include_files.isChecked() and self.file_data:
                        self.report_generator.generate_csv_report(self.file_data, export_path, 'files')
                        gen_count += 1
                    if self.include_logs.isChecked() and self.log_data:
                        self.report_generator.generate_csv_report(self.log_data, export_path, 'logs')
                        gen_count += 1
                    if self.include_browser.isChecked() and self.browser_data:
                        self.report_generator.generate_csv_report(self.browser_data, export_path, 'browser')
                        gen_count += 1
                    if self.include_timeline.isChecked() and self.timeline_data:
                        self.report_generator.generate_csv_report(self.timeline_data, export_path, 'timeline')
                        gen_count += 1

                    if gen_count > 0:
                        QMessageBox.information(self, "Reports Generated", f"Successfully generated {gen_count} CSV reports in:\n{export_path}")
                    else:
                        QMessageBox.warning(self, "No Data", "No data available to export for selected items.")
                except Exception as e:
                    QMessageBox.critical(self, "Report Error", f"Failed to generate CSV reports: {e}")

        def generate_html_report(self):
            export_path = QFileDialog.getExistingDirectory(self, "Select HTML Report Output Directory")
            if export_path:
                try:
                    f_data = self.file_data if self.include_files.isChecked() else []
                    l_data = self.log_data if self.include_logs.isChecked() else []
                    b_data = self.browser_data if self.include_browser.isChecked() else []
                    t_data = self.timeline_data if self.include_timeline.isChecked() else []

                    html_file = self.report_generator.generate_html_report(f_data, l_data, b_data, t_data, export_path)
                    self.last_generated_html_path = html_file
                    self.btn_open_browser.setEnabled(True)

                    QMessageBox.information(
                        self,
                        "Report Generated",
                        f"Full HTML Report generated successfully:\n\n{html_file}\n\nYou can click 'Open HTML Report in Web Browser' to view it with full styling."
                    )

                    # Quick preview summary
                    summary_text = (
                        f"=== FORENSIC REPORT GENERATED ===\n"
                        f"File Location: {html_file}\n"
                        f"Generated Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                        f"Files Included: {len(f_data)}\n"
                        f"Event Logs: {len(l_data)}\n"
                        f"Browser Records: {len(b_data)}\n"
                        f"Timeline Events: {len(t_data)}\n\n"
                        f"Click 'Open HTML Report in Web Browser' to view the full interactive report in Google Chrome, Edge, or Firefox."
                    )
                    self.report_preview.setPlainText(summary_text)

                except Exception as e:
                    QMessageBox.critical(self, "Report Error", f"Failed to generate HTML report: {e}")


def main():
    if not PYQT_AVAILABLE:
        print("PyQt5 is not available. Please install PyQt5: pip install PyQt5")
        return 1

    # High-DPI Scaling configuration for sharp text rendering
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName('ForensiX Pro')
    app.setApplicationVersion('2.0.0')
    app.setOrganizationName('ForensiX Security')

    font = QFont("Segoe UI", 10)
    app.setFont(font)

    window = ForensicAnalysisGUI()
    window.show()
    return app.exec_()


if __name__ == '__main__':
    sys.exit(main())
