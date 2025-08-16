#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Digital Security Toolkit - Main Application
Automatically runs with admin privileges
"""

import os
import sys
import ctypes
import subprocess
from pathlib import Path

def is_admin():
    """Check if running with admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Restart the application with admin privileges"""
    try:
        if not is_admin():
            # Get the current script path
            script_path = os.path.abspath(__file__)
            
            # Get Python executable path
            python_exe = sys.executable
            
            # Method 1: Try using subprocess with runas
            try:
                print("Attempting to restart with admin privileges...")
                result = subprocess.run([
                    python_exe, script_path
                ], shell=True, capture_output=True, text=True)
                
                # If we get here, the new process started successfully
                print("✅ Application restarted with admin privileges!")
                sys.exit(0)
                
            except subprocess.CalledProcessError:
                pass
            
            # Method 2: Fallback to ShellExecuteW
            try:
                result = ctypes.windll.shell32.ShellExecuteW(
                    None, 
                    "runas",  # Run as administrator
                    python_exe, 
                    f'"{script_path}"', 
                    None, 
                    1  # SW_SHOWNORMAL
                )
                
                # Check if elevation was successful
                if result > 32:  # Success
                    print("✅ Restarting with admin privileges...")
                    # Exit current instance gracefully
                    sys.exit(0)
                else:
                    print("❌ Failed to elevate privileges. Running in limited mode.")
                    return False
                    
            except Exception as e:
                print(f"❌ ShellExecuteW failed: {e}")
                return False
            
    except Exception as e:
        print(f"❌ Error elevating privileges: {e}")
        return False

def main():
    """Main application entry point"""
    print("=== Digital Security Toolkit ===")
    print("Checking admin privileges...")
    
    # Check admin privileges
    if not is_admin():
        print("⚠️ Application requires admin privileges for full file recovery features.")
        print("Attempting to restart with admin privileges...")
        
        # Try to restart with admin privileges
        if run_as_admin():
            return  # Exit if restart was successful
        else:
            print("⚠️ Continuing in limited mode (some features disabled)")
    else:
        print("✅ Running with admin privileges - All features enabled!")
    
    # Import and run the main application
    try:
        # Add current directory to Python path
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        # Import required modules
        from gui.main_window import MainWindow
        from utils.config import Config
        from utils.logger import setup_logger, get_logger
        import tkinter as tk
        
        # Setup configuration
        config = Config()
        
        # Setup logger
        log_file = os.path.join("logs", "dst.log")
        setup_logger("dst_main", log_file)
        logger = get_logger("dst_main")
        
        # Create and run the main application
        root = tk.Tk()
        root.title("Digital Security Toolkit - Admin Mode" if is_admin() else "Digital Security Toolkit - Limited Mode")
        root.geometry("1200x800")
        
        # Prevent window from being resized too small
        root.minsize(800, 600)
        
        app = MainWindow(root, config, logger)
        
        # Log startup
        if is_admin():
            logger.info("Application started with admin privileges")
        else:
            logger.warning("Application started without admin privileges - limited functionality")
        
        print("Starting GUI...")
        root.mainloop()
        
    except ImportError as e:
        print(f"❌ Error importing application modules: {e}")
        print("Make sure all required modules are available.")
        input("Press Enter to exit...")
    except Exception as e:
        print(f"❌ Error running application: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main() 