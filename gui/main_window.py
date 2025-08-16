#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Glavni prozor GUI-a za Digital Security Toolkit
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
from datetime import datetime

from gui.tabs.file_recovery_tab import FileRecoveryTab
from gui.tabs.yara_scan_tab import YaraScanTab
from gui.tabs.integrity_tab import IntegrityTab
from gui.tabs.timeline_tab import TimelineTab
from gui.tabs.monitoring_tab import MonitoringTab
from gui.tabs.reports_tab import ReportsTab
from utils.logger import LoggerMixin

class MainWindow(LoggerMixin):
    """Glavni prozor aplikacije sa tabovima"""
    
    def __init__(self, root, config, logger):
        super().__init__("MainWindow")
        self.root = root
        self.config = config
        self.logger = logger
        
        # Aktivni procesi
        self.active_processes = []
        self.process_lock = threading.Lock()
        
        self.setup_ui()
        self.log_info("Glavni prozor inicijalizovan")
    
    def setup_ui(self):
        """Postavljanje korisničkog interfejsa"""
        # Glavni frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self.setup_header()
        
        # Notebook (tabovi)
        self.setup_notebook()
        
        # Status bar
        self.setup_status_bar()
        
        # Menu bar
        self.setup_menu()
    
    def setup_header(self):
        """Postavljanje header-a"""
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Naslov
        title_label = ttk.Label(
            header_frame, 
            text="Digital Security Toolkit v1.0",
            font=("Arial", 16, "bold")
        )
        title_label.pack(side=tk.LEFT)
        
        # Admin privileges indicator
        if self.is_admin():
            admin_label = ttk.Label(
                header_frame,
                text="🔒 ADMIN MODE",
                foreground="green",
                font=("Arial", 10, "bold")
            )
            admin_label.pack(side=tk.LEFT, padx=(20, 0))
            self.log_info("Running with admin privileges - File recovery features enabled!")
        else:
            admin_label = ttk.Label(
                header_frame,
                text="⚠️ LIMITED MODE",
                foreground="orange",
                font=("Arial", 10, "bold")
            )
            admin_label.pack(side=tk.LEFT, padx=(20, 0))
            self.log_warning("Running without admin privileges - Limited file recovery features")
        
        # Vrijeme
        self.time_label = ttk.Label(header_frame, font=("Arial", 10))
        self.time_label.pack(side=tk.RIGHT)
        self.update_time()
    
    def setup_notebook(self):
        """Postavljanje notebook-a sa tabovima"""
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Kreiranje tabova
        self.tabs = {}
        
        # File Recovery Tab
        self.tabs['file_recovery'] = FileRecoveryTab(
            self.notebook, self.config, self.logger
        )
        self.notebook.add(
            self.tabs['file_recovery'], 
            text="Oporavak podataka"
        )
        
        # YARA Scan Tab
        self.tabs['yara_scan'] = YaraScanTab(
            self.notebook, self.config, self.logger
        )
        self.notebook.add(
            self.tabs['yara_scan'], 
            text="YARA skeniranje"
        )
        
        # Integrity Tab
        self.tabs['integrity'] = IntegrityTab(
            self.notebook, self.config, self.logger
        )
        self.notebook.add(
            self.tabs['integrity'], 
            text="Provjera integriteta"
        )
        
        # Timeline Tab
        self.tabs['timeline'] = TimelineTab(
            self.notebook, self.config, self.logger
        )
        self.notebook.add(
            self.tabs['timeline'], 
            text="Vremenska linija"
        )
        
        # Monitoring Tab
        self.tabs['monitoring'] = MonitoringTab(
            self.notebook, self.config, self.logger
        )
        self.notebook.add(
            self.tabs['monitoring'], 
            text="Nadzor sistema"
        )
        
        # Reports Tab
        self.tabs['reports'] = ReportsTab(
            self.notebook, self.config, self.logger
        )
        self.notebook.add(
            self.tabs['reports'], 
            text="Izvještaji"
        )
        
        # Event handler za promjenu tabova
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
    
    def setup_status_bar(self):
        """Postavljanje status bara"""
        self.status_frame = ttk.Frame(self.main_frame)
        self.status_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Status label
        self.status_label = ttk.Label(
            self.status_frame, 
            text="Spremno",
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.status_frame,
            variable=self.progress_var,
            mode='determinate'
        )
        self.progress_bar.pack(side=tk.RIGHT, padx=(10, 0))
    
    def setup_menu(self):
        """Postavljanje menija"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Fajl", menu=file_menu)
        file_menu.add_command(label="Izlaz", command=self.on_closing)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Alati", menu=tools_menu)
        tools_menu.add_command(label="Konfiguracija", command=self.show_config)
        tools_menu.add_separator()
        tools_menu.add_command(label="Očisti temp fajlove", command=self.cleanup_temp)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Pomoć", menu=help_menu)
        help_menu.add_command(label="O aplikaciji", command=self.show_about)
        help_menu.add_command(label="Dokumentacija", command=self.show_docs)
    
    def update_time(self):
        """Ažuriranje vremena u header-u"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)  # Ažuriranje svake sekunde
    
    def on_tab_changed(self, event):
        """Handler za promjenu tabova"""
        current_tab = self.notebook.select()
        tab_name = self.notebook.tab(current_tab, "text")
        self.status_label.config(text=f"Aktivni tab: {tab_name}")
        self.log_info(f"Prebačen na tab: {tab_name}")
    
    def update_status(self, message, progress=None):
        """Ažuriranje status bara"""
        self.status_label.config(text=message)
        if progress is not None:
            self.progress_var.set(progress)
        self.root.update_idletasks()
    
    def add_active_process(self, process):
        """Dodavanje aktivnog procesa"""
        with self.process_lock:
            self.active_processes.append(process)
    
    def remove_active_process(self, process):
        """Uklanjanje aktivnog procesa"""
        with self.process_lock:
            if process in self.active_processes:
                self.active_processes.remove(process)
    
    def stop_all_processes(self):
        """Zaustavljanje svih aktivnih procesa"""
        with self.process_lock:
            for process in self.active_processes:
                try:
                    if hasattr(process, 'stop'):
                        process.stop()
                    elif hasattr(process, 'terminate'):
                        process.terminate()
                except Exception as e:
                    self.log_error(f"Greška pri zaustavljanju procesa: {e}")
            self.active_processes.clear()
    
    def show_config(self):
        """Prikaz konfiguracije"""
        try:
            from gui.dialogs.config_dialog import ConfigDialog
            dialog = ConfigDialog(self.root, self.config)
            self.root.wait_window(dialog.dialog)
        except Exception as e:
            self.log_error(f"Greška pri otvaranju konfiguracije: {e}")
            messagebox.showerror("Greška", f"Greška pri otvaranju konfiguracije: {e}")
    
    def cleanup_temp(self):
        """Čišćenje temp fajlova"""
        try:
            temp_dir = "temp"
            if os.path.exists(temp_dir):
                count = 0
                for file in os.listdir(temp_dir):
                    file_path = os.path.join(temp_dir, file)
                    try:
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                            count += 1
                    except Exception as e:
                        self.log_error(f"Greška pri brisanju {file_path}: {e}")
                
                self.log_info(f"Očišćeno {count} temp fajlova")
                messagebox.showinfo("Čišćenje", f"Očišćeno {count} temp fajlova")
            else:
                messagebox.showinfo("Čišćenje", "Temp direktorijum ne postoji")
        except Exception as e:
            self.log_error(f"Greška pri čišćenju: {e}")
            messagebox.showerror("Greška", f"Greška pri čišćenju: {e}")
    
    def show_about(self):
        """Prikaz o aplikaciji"""
        about_text = """
Digital Security Toolkit v1.0

Modularni sigurnosni softverski paket dizajniran za praćenje, 
analizu i zaštitu uređaja od različitih sigurnosnih prijetnji.

Funkcionalnosti:
• Oporavak podataka (File Carving & Recovery)
• YARA skeniranje
• Provjera integriteta
• Vremenska linija aktivnosti
• Nadzor sistema u stvarnom vremenu
• Generator izvještaja

Autor: Harun Mutevelić
Licenca: PMF
        """
        messagebox.showinfo("O aplikaciji", about_text)
    
    def show_docs(self):
        """Prikaz dokumentacije"""
        messagebox.showinfo("Dokumentacija", 
                           "Dokumentacija je dostupna u README.md fajlu")
    
    def on_closing(self):
        """Handler za zatvaranje aplikacije"""
        try:
            # Zaustavljanje svih procesa
            self.stop_all_processes()
            
            # Zatvaranje aplikacije
            self.root.quit()
            
        except Exception as e:
            self.log_error(f"Greška pri zatvaranju: {e}")
            self.root.quit() 

    def is_admin(self):
        """Check if running with admin privileges"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False 