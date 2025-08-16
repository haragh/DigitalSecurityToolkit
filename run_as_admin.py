#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Alternative admin launcher for Digital Security Toolkit
Uses runas command for better UAC handling
"""

import os
import sys
import subprocess
import ctypes

def is_admin():
    """Check if running with admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    """Main launcher function"""
    print("=== Digital Security Toolkit - Admin Launcher ===")
    
    # Check if already running as admin
    if is_admin():
        print("✅ Already running with admin privileges!")
        print("Starting main application...")
        
        # Start main application
        main_script = os.path.join(os.path.dirname(__file__), "main.py")
        subprocess.run([sys.executable, main_script])
        return
    
    # Not running as admin - try to elevate
    print("⚠️ Not running with admin privileges.")
    print("Attempting to restart with admin privileges...")
    
    # Get paths
    script_path = os.path.abspath(__file__)
    main_script = os.path.join(os.path.dirname(script_path), "main.py")
    python_exe = sys.executable
    
    try:
        # Method 1: Use runas command
        print("Trying runas command...")
        cmd = f'runas /user:Administrator "{python_exe}" "{main_script}"'
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Successfully started with admin privileges!")
        else:
            print("❌ runas failed, trying alternative method...")
            
            # Method 2: Use PowerShell
            ps_cmd = f'powershell -Command "Start-Process -FilePath \'{python_exe}\' -ArgumentList \'{main_script}\' -Verb RunAs"'
            subprocess.run(ps_cmd, shell=True)
            
    except Exception as e:
        print(f"❌ Error elevating privileges: {e}")
        print("Starting in limited mode...")
        
        # Start main application in limited mode
        subprocess.run([python_exe, main_script])

if __name__ == "__main__":
    main() 