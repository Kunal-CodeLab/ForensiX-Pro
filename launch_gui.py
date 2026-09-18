#!/usr/bin/env python3
"""
ForensiX Pro - Safe Launcher
Digital Forensics & Incident Response Suite
"""

import sys
import traceback
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from forensic_analysis_tool import ForensicAnalysisGUI, PYQT_AVAILABLE

def main():
    """Main launcher function with comprehensive error handling"""
    
    if not PYQT_AVAILABLE:
        print("ERROR: PyQt5 is not available.")
        print("Please install PyQt5: pip install PyQt5")
        input("Press Enter to exit...")
        return 1
    
    try:
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
        
        print("Starting ForensiX Pro...")
        window = ForensicAnalysisGUI()
        window.show()
        
        print("ForensiX Pro launched successfully!")
        return app.exec_()
        
    except Exception as e:
        error_msg = f"Failed to start ForensiX Pro:\n{str(e)}\n\nFull error:\n{traceback.format_exc()}"
        print(error_msg)
        
        try:
            app = QApplication.instance()
            if app is None:
                app = QApplication(sys.argv)
            QMessageBox.critical(None, "ForensiX Pro Error", error_msg)
        except Exception:
            pass
        
        input("Press Enter to exit...")
        return 1

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
