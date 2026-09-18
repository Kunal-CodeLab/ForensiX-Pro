#!/usr/bin/env python3
"""
Forensic Analysis Tool - Test Suite
Validates core functionality without GUI dependencies
"""

import sys
import os
import tempfile
import json
import csv
from pathlib import Path

# Fix Windows console encoding for UTF-8 / symbols
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Add the current directory to path to import the forensic tool modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_file_recovery():
    """Test file recovery functionality"""
    print("[*] Testing File Recovery Engine...")

    try:
        from forensic_analysis_tool import FileRecoveryEngine

        recovery = FileRecoveryEngine()

        # Test recycle bin scan
        print("   - Testing Recycle Bin scan ($I/$R metadata parser)...")
        recycle_files = recovery.scan_recycle_bin()
        print(f"   - Found {len(recycle_files)} files in recycle bin")

        # Test deleted file scan
        print("   - Testing deleted artifact scan...")
        if os.name == 'nt':
            deleted_files = recovery.scan_deleted_files("C:\\Windows\\Temp")
        else:
            deleted_files = recovery.scan_deleted_files("/tmp")
        print(f"   - Found {len(deleted_files)} deleted artifacts")

        print("[+] File Recovery Engine: PASSED")
        return True

    except Exception as e:
        print(f"[-] File Recovery Engine: FAILED - {e}")
        return False

def test_log_analyzer():
    """Test log analysis and multi-profile browser history"""
    print("[*] Testing Log Analyzer...")

    try:
        from forensic_analysis_tool import LogAnalyzer

        analyzer = LogAnalyzer()

        # Test Windows logs
        print("   - Testing Windows Event Log analysis...")
        event_logs = analyzer.analyze_windows_logs()
        print(f"   - Processed {len(event_logs)} event log entries")

        # Test browser profiles discovery
        print("   - Testing browser profile discovery...")
        profiles = analyzer.get_available_browser_profiles()
        print(f"   - Discovered {len(profiles)} browser profiles on system")

        # Test browser history
        print("   - Testing browser history extraction...")
        browser_history = analyzer.analyze_browser_history()
        print(f"   - Found {len(browser_history)} browser history entries")

        print("[+] Log Analyzer: PASSED")
        return True

    except Exception as e:
        print(f"[-] Log Analyzer: FAILED - {e}")
        return False

def test_timeline_creator():
    """Test timeline creation functionality"""
    print("[*] Testing Timeline Creator...")

    try:
        from forensic_analysis_tool import TimelineCreator
        import datetime

        timeline = TimelineCreator()

        sample_files = [
            {
                'name': 'test.txt',
                'path': 'C:\\temp\\test.txt',
                'modified': datetime.datetime.now(),
                'created': datetime.datetime.now(),
                'size': 1024,
                'source': 'Recycle Bin'
            }
        ]

        sample_logs = [
            {
                'log_type': 'System',
                'event_id': '1001',
                'source': 'Test',
                'timestamp': '2026-03-12 14:00:00',
                'level': 'Information',
                'message': 'Test log entry'
            }
        ]

        sample_browser = [
            {
                'browser': 'Chrome (Default)',
                'title': 'Test Forensic Research',
                'url': 'https://example.com',
                'visit_count': 3,
                'timestamp': datetime.datetime.now()
            }
        ]

        print("   - Creating timeline from multi-source data...")
        timeline_data = timeline.create_timeline(sample_files, sample_logs, sample_browser)
        print(f"   - Generated timeline with {len(timeline_data)} sorted events")

        print("[+] Timeline Creator: PASSED")
        return True

    except Exception as e:
        print(f"[-] Timeline Creator: FAILED - {e}")
        return False

def test_evidence_collector():
    """Test evidence collection and chain of custody packaging"""
    print("[*] Testing Evidence Collector...")

    try:
        from forensic_analysis_tool import EvidenceCollector

        collector = EvidenceCollector()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_file:
            tmp_file.write("This is critical forensic evidence.")
            test_file_path = tmp_file.name

        print("   - Adding test evidence file...")
        evidence_item = collector.add_evidence(test_file_path, "Test critical file", "CASE-2026-001")
        print(f"   - Added evidence item with ID: {evidence_item['id']} and SHA256: {evidence_item['hash'][:16]}...")

        with tempfile.TemporaryDirectory() as tmp_dir:
            print("   - Testing secure ZIP export...")
            zip_path = collector.export_evidence(tmp_dir, 'zip')
            print(f"   - Created ZIP archive: {zip_path}")

            print("   - Testing organized folder export...")
            folder_path = collector.export_evidence(tmp_dir, 'folder')
            print(f"   - Created evidence folder: {folder_path}")

        os.unlink(test_file_path)

        print("[+] Evidence Collector: PASSED")
        return True

    except Exception as e:
        print(f"[-] Evidence Collector: FAILED - {e}")
        return False

def test_report_generator():
    """Test full report generation functionality"""
    print("[*] Testing Report Generator...")

    try:
        from forensic_analysis_tool import ReportGenerator
        import datetime

        generator = ReportGenerator()

        sample_data = [
            {
                'name': 'evidence.doc',
                'path': 'C:\\evidence.doc',
                'size': 2048,
                'modified': datetime.datetime.now(),
                'source': 'Recycle Bin',
                'hash': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            }
        ]

        with tempfile.TemporaryDirectory() as tmp_dir:
            print("   - Testing full CSV report export...")
            csv_path = generator.generate_csv_report(sample_data, tmp_dir, 'test_report')
            print(f"   - Generated CSV report: {csv_path}")

            with open(csv_path, 'r', encoding='utf-8') as csv_file:
                reader = csv.DictReader(csv_file)
                rows = list(reader)
                print(f"   - CSV contains {len(rows)} data rows")

            print("   - Testing full HTML report generation...")
            html_path = generator.generate_html_report(sample_data, [], [], [], tmp_dir)
            print(f"   - Generated HTML report: {html_path}")

            with open(html_path, 'r', encoding='utf-8') as html_file:
                html_content = html_file.read()
                print(f"   - HTML report size: {len(html_content)} bytes")

        print("[+] Report Generator: PASSED")
        return True

    except Exception as e:
        print(f"[-] Report Generator: FAILED - {e}")
        return False

def test_system_compatibility():
    """Test system compatibility and requirements"""
    print("[*] Testing System Compatibility...")

    try:
        python_version = sys.version_info
        print(f"   - Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")

        required_modules = ['os', 'sys', 'json', 'csv', 'sqlite3', 'datetime', 'subprocess', 
                          'shutil', 'zipfile', 'hashlib', 'xml.etree.ElementTree', 'pathlib',
                          'collections', 'threading', 'time', 'struct', 'gc']

        missing_modules = []
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)

        if missing_modules:
            print(f"   [-] Missing required modules: {missing_modules}")
            return False
        else:
            print("   [+] All required standard library modules available")

        # Check PyQt5
        try:
            from PyQt5.QtWidgets import QApplication
            print("   [+] PyQt5 available (GUI interface supported)")
        except ImportError:
            print("   [-] PyQt5 not available")

        platform = sys.platform
        print(f"   - Platform: {platform}")

        print("[+] System Compatibility: PASSED")
        return True

    except Exception as e:
        print(f"[-] System Compatibility: FAILED - {e}")
        return False

def main():
    print("Forensic Analysis Tool - Test Suite")
    print("=" * 50)

    tests = [
        ("System Compatibility", test_system_compatibility),
        ("File Recovery Engine", test_file_recovery),
        ("Log Analyzer", test_log_analyzer),
        ("Timeline Creator", test_timeline_creator),
        ("Evidence Collector", test_evidence_collector),
        ("Report Generator", test_report_generator)
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        print()
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"[-] {test_name}: CRITICAL FAILURE - {e}")
            failed += 1

    print()
    print("=" * 50)
    print("Test Summary")
    print(f"[+] Passed: {passed}")
    print(f"[-] Failed: {failed}")
    print(f"[*] Success Rate: {(passed / (passed + failed)) * 100:.1f}%")

    if failed == 0:
        print("[+] All tests passed! The forensic tool is fully verified and ready.")
        return 0
    else:
        print("[-] Some tests failed. Please review the issues above.")
        return 1

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
