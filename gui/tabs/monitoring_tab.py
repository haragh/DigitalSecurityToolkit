#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Monitoring Tab - Nadzor sistema u stvarnom vremenu
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import psutil
from datetime import datetime

from utils.logger import LoggerMixin
from modules.system_monitor import SystemMonitor

class MonitoringTab(ttk.Frame, LoggerMixin):
    """Tab za nadzor sistema"""
    
    def __init__(self, parent, config, logger):
        ttk.Frame.__init__(self, parent)
        LoggerMixin.__init__(self, "MonitoringTab")
        
        self.config = config
        self.logger = logger
        self.monitor = SystemMonitor(config, logger)
        
        self.monitoring_active = False
        self.monitoring_thread = None
        
        self.setup_ui()
        self.log_info("Monitoring tab inicijalizovan")
    
    def setup_ui(self):
        """Postavljanje korisničkog interfejsa"""
        # Glavni frame
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Kontrole
        self.setup_controls(main_frame)
        
        # Status sistema
        self.setup_system_status(main_frame)
        
        # Aktivnosti
        self.setup_activities(main_frame)
        
        # Progress
        self.setup_progress(main_frame)
    
    def setup_controls(self, parent):
        """Postavljanje kontrolnih elemenata"""
        controls_frame = ttk.LabelFrame(parent, text="Kontrole", padding=10)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Opcije nadzora
        options_frame = ttk.Frame(controls_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.monitor_processes_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Nadzori procese", variable=self.monitor_processes_var).pack(side=tk.LEFT)
        
        self.monitor_files_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Nadzori fajlove", variable=self.monitor_files_var).pack(side=tk.LEFT, padx=(20, 0))
        
        self.monitor_network_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Nadzori mrežu", variable=self.monitor_network_var).pack(side=tk.LEFT, padx=(20, 0))
        
        self.monitor_system_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Nadzori sistem", variable=self.monitor_system_var).pack(side=tk.LEFT, padx=(20, 0))
        
        # Interval
        interval_frame = ttk.Frame(controls_frame)
        interval_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(interval_frame, text="Interval provjere (sekunde):").pack(side=tk.LEFT)
        self.interval_var = tk.IntVar(value=5)
        interval_spin = ttk.Spinbox(interval_frame, from_=1, to=60, textvariable=self.interval_var, width=10)
        interval_spin.pack(side=tk.LEFT, padx=(10, 0))
        
        # Dugmad
        button_frame = ttk.Frame(controls_frame)
        button_frame.pack(fill=tk.X)
        
        self.start_button = ttk.Button(button_frame, text="Pokreni nadzor", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Zaustavi nadzor", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="Očisti log", command=self.clear_log).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Sačuvaj log", command=self.save_log).pack(side=tk.LEFT)
    
    def setup_system_status(self, parent):
        """Postavljanje statusa sistema"""
        status_frame = ttk.LabelFrame(parent, text="Status sistema", padding=10)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        # CPU i memorija
        resources_frame = ttk.Frame(status_frame)
        resources_frame.pack(fill=tk.X, pady=(0, 10))
        
        # CPU
        cpu_frame = ttk.Frame(resources_frame)
        cpu_frame.pack(side=tk.LEFT, padx=(0, 20))
        
        ttk.Label(cpu_frame, text="CPU:").pack(side=tk.LEFT)
        self.cpu_label = ttk.Label(cpu_frame, text="0%")
        self.cpu_label.pack(side=tk.LEFT, padx=(5, 0))
        
        self.cpu_bar = ttk.Progressbar(cpu_frame, length=100, mode='determinate')
        self.cpu_bar.pack(side=tk.LEFT, padx=(10, 0))
        
        # Memorija
        memory_frame = ttk.Frame(resources_frame)
        memory_frame.pack(side=tk.LEFT, padx=(0, 20))
        
        ttk.Label(memory_frame, text="Memorija:").pack(side=tk.LEFT)
        self.memory_label = ttk.Label(memory_frame, text="0%")
        self.memory_label.pack(side=tk.LEFT, padx=(5, 0))
        
        self.memory_bar = ttk.Progressbar(memory_frame, length=100, mode='determinate')
        self.memory_bar.pack(side=tk.LEFT, padx=(10, 0))
        
        # Disk
        disk_frame = ttk.Frame(resources_frame)
        disk_frame.pack(side=tk.LEFT)
        
        ttk.Label(disk_frame, text="Disk:").pack(side=tk.LEFT)
        self.disk_label = ttk.Label(disk_frame, text="0%")
        self.disk_label.pack(side=tk.LEFT, padx=(5, 0))
        
        self.disk_bar = ttk.Progressbar(disk_frame, length=100, mode='determinate')
        self.disk_bar.pack(side=tk.LEFT, padx=(10, 0))
        
        # Detaljne informacije
        details_frame = ttk.Frame(status_frame)
        details_frame.pack(fill=tk.X)
        
        # Procesi
        processes_frame = ttk.Frame(details_frame)
        processes_frame.pack(side=tk.LEFT, padx=(0, 20))
        
        ttk.Label(processes_frame, text="Aktivni procesi:").pack()
        self.processes_label = ttk.Label(processes_frame, text="0")
        self.processes_label.pack()
        
        # Mreža
        network_frame = ttk.Frame(details_frame)
        network_frame.pack(side=tk.LEFT, padx=(0, 20))
        
        ttk.Label(network_frame, text="Mrežne konekcije:").pack()
        self.network_label = ttk.Label(network_frame, text="0")
        self.network_label.pack()
        
        # Fajlovi
        files_frame = ttk.Frame(details_frame)
        files_frame.pack(side=tk.LEFT)
        
        ttk.Label(files_frame, text="Fajl aktivnosti:").pack()
        self.files_label = ttk.Label(files_frame, text="0")
        self.files_label.pack()
    
    def setup_activities(self, parent):
        """Postavljanje prikaza aktivnosti"""
        activities_frame = ttk.LabelFrame(parent, text="Aktivnosti", padding=10)
        activities_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Treeview za aktivnosti
        columns = ('Vrijeme', 'Tip', 'Detalji', 'Status')
        self.activities_tree = ttk.Treeview(activities_frame, columns=columns, show='headings', height=10)
        
        # Postavljanje kolona
        for col in columns:
            self.activities_tree.heading(col, text=col)
            if col == 'Vrijeme':
                self.activities_tree.column(col, width=150)
            elif col == 'Tip':
                self.activities_tree.column(col, width=100)
            elif col == 'Status':
                self.activities_tree.column(col, width=100)
            else:
                self.activities_tree.column(col, width=300)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(activities_frame, orient=tk.VERTICAL, command=self.activities_tree.yview)
        self.activities_tree.configure(yscrollcommand=scrollbar.set)
        
        self.activities_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Context menu
        self.setup_context_menu()
    
    def setup_progress(self, parent):
        """Postavljanje progress bara"""
        progress_frame = ttk.Frame(parent)
        progress_frame.pack(fill=tk.X)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, mode='indeterminate')
        self.progress_bar.pack(fill=tk.X, side=tk.LEFT, expand=True)
        
        self.status_label = ttk.Label(progress_frame, text="Nadzor zaustavljen")
        self.status_label.pack(side=tk.RIGHT, padx=(10, 0))
    
    def setup_context_menu(self):
        """Postavljanje context menija"""
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Kopiraj detalje", command=self.copy_details)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Označi kao važno", command=self.mark_important)
        
        self.activities_tree.bind("<Button-3>", self.show_context_menu)
    
    def start_monitoring(self):
        """Pokretanje nadzora"""
        try:
            if self.monitoring_active:
                return
            
            # Postavljanje UI-a
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.progress_bar.start()
            self.status_label.config(text="Nadzor aktivan")
            
            # Pokretanje nadzora
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self.run_monitoring)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()
            
            self.log_info("Nadzor sistema pokrenut")
            
        except Exception as e:
            self.log_error(f"Greška pri pokretanju nadzora: {e}")
            messagebox.showerror("Greška", f"Greška pri pokretanju nadzora: {e}")
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Zaustavljanje nadzora"""
        try:
            self.monitoring_active = False
            
            # Postavljanje UI-a
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.progress_bar.stop()
            self.status_label.config(text="Nadzor zaustavljen")
            
            self.log_info("Nadzor sistema zaustavljen")
            
        except Exception as e:
            self.log_error(f"Greška pri zaustavljanju nadzora: {e}")
    
    def run_monitoring(self):
        """Izvršavanje nadzora"""
        try:
            interval = self.interval_var.get()
            
            while self.monitoring_active:
                # Ažuriranje statusa sistema
                self.update_system_status()
                
                # Provjera aktivnosti
                if self.monitor_processes_var.get():
                    self.check_processes()
                
                if self.monitor_files_var.get():
                    self.check_files()
                
                if self.monitor_network_var.get():
                    self.check_network()
                
                if self.monitor_system_var.get():
                    self.check_system()
                
                # Pauza
                time.sleep(interval)
                
        except Exception as e:
            self.log_error(f"Greška u nadzoru: {e}")
            self.stop_monitoring()
    
    def update_system_status(self):
        """Ažuriranje statusa sistema"""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            self.cpu_label.config(text=f"{cpu_percent:.1f}%")
            self.cpu_bar['value'] = cpu_percent
            
            # Memorija
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            self.memory_label.config(text=f"{memory_percent:.1f}%")
            self.memory_bar['value'] = memory_percent
            
            # Disk
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            self.disk_label.config(text=f"{disk_percent:.1f}%")
            self.disk_bar['value'] = disk_percent
            
            # Broj procesa
            process_count = len(psutil.pids())
            self.processes_label.config(text=str(process_count))
            
            # Mrežne konekcije
            network_connections = len(psutil.net_connections())
            self.network_label.config(text=str(network_connections))
            
        except Exception as e:
            self.log_error(f"Greška pri ažuriranju statusa: {e}")
    
    def check_processes(self):
        """Provjera procesa"""
        try:
            # Provjera novih procesa
            new_processes = self.monitor.check_new_processes()
            for process in new_processes:
                self.add_activity('Proces', f"Novi proces: {process['name']} (PID: {process['pid']})", 'Info')
            
            # Provjera sumnjivih procesa
            suspicious_processes = self.monitor.check_suspicious_processes()
            for process in suspicious_processes:
                self.add_activity('Proces', f"Sumnjiv proces: {process['name']} - {process['reason']}", 'Upozorenje')
                
        except Exception as e:
            self.log_error(f"Greška pri provjeri procesa: {e}")
    
    def check_files(self):
        """Provjera fajlova"""
        try:
            # Provjera fajl aktivnosti
            file_activities = self.monitor.check_file_activities()
            for activity in file_activities:
                self.add_activity('Fajl', f"{activity['action']}: {activity['path']}", 'Info')
                
        except Exception as e:
            self.log_error(f"Greška pri provjeri fajlova: {e}")
    
    def check_network(self):
        """Provjera mreže"""
        try:
            # Provjera mrežnih konekcija
            network_activities = self.monitor.check_network_activities()
            for activity in network_activities:
                self.add_activity('Mreža', f"Konekcija: {activity['local']} -> {activity['remote']}", 'Info')
                
        except Exception as e:
            self.log_error(f"Greška pri provjeri mreže: {e}")
    
    def check_system(self):
        """Provjera sistema"""
        try:
            # Provjera sistemskih događaja
            system_events = self.monitor.check_system_events()
            for event in system_events:
                self.add_activity('Sistem', f"{event['type']}: {event['description']}", event['severity'])
                
        except Exception as e:
            self.log_error(f"Greška pri provjeri sistema: {e}")
    
    def add_activity(self, activity_type, details, status):
        """Dodavanje aktivnosti u listu"""
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            # Dodavanje u treeview
            self.activities_tree.insert('', 0, values=(timestamp, activity_type, details, status))
            
            # Ograničavanje broja stavki
            items = self.activities_tree.get_children()
            if len(items) > 1000:
                self.activities_tree.delete(items[-1])
            
            # Ažuriranje brojača
            if activity_type == 'Fajl':
                current_count = int(self.files_label.cget("text"))
                self.files_label.config(text=str(current_count + 1))
                
        except Exception as e:
            self.log_error(f"Greška pri dodavanju aktivnosti: {e}")
    
    def clear_log(self):
        """Čišćenje log-a"""
        for item in self.activities_tree.get_children():
            self.activities_tree.delete(item)
        
        self.files_label.config(text="0")
        self.log_info("Log aktivnosti očišćen")
    
    def save_log(self):
        """Čuvanje log-a"""
        try:
            import json
            
            file_path = filedialog.asksaveasfilename(
                title="Sačuvaj log",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if file_path:
                activities = []
                for item in self.activities_tree.get_children():
                    values = self.activities_tree.item(item)['values']
                    activities.append({
                        'timestamp': values[0],
                        'type': values[1],
                        'details': values[2],
                        'status': values[3]
                    })
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(activities, f, indent=4, ensure_ascii=False)
                
                messagebox.showinfo("Info", f"Log sačuvan u {file_path}")
                
        except Exception as e:
            self.log_error(f"Greška pri čuvanju log-a: {e}")
            messagebox.showerror("Greška", f"Greška pri čuvanju log-a: {e}")
    
    def show_context_menu(self, event):
        """Prikaz context menija"""
        try:
            item = self.activities_tree.identify_row(event.y)
            if item:
                self.activities_tree.selection_set(item)
                self.context_menu.post(event.x_root, event.y_root)
        except Exception as e:
            self.log_error(f"Greška pri prikazu context menija: {e}")
    
    def copy_details(self):
        """Kopiranje detalja u clipboard"""
        try:
            selection = self.activities_tree.selection()
            if selection:
                item = self.activities_tree.item(selection[0])
                values = item['values']
                details = f"Vrijeme: {values[0]}\nTip: {values[1]}\nDetalji: {values[2]}\nStatus: {values[3]}"
                
                self.clipboard_clear()
                self.clipboard_append(details)
                messagebox.showinfo("Info", "Detalji kopirani u clipboard")
        except Exception as e:
            self.log_error(f"Greška pri kopiranju detalja: {e}")
            messagebox.showerror("Greška", f"Greška pri kopiranju detalja: {e}")
    
    def mark_important(self):
        """Označavanje kao važno"""
        try:
            selection = self.activities_tree.selection()
            if selection:
                item = self.activities_tree.item(selection[0])
                values = list(item['values'])
                values[3] = "VAŽNO"
                self.activities_tree.item(selection[0], values=values)
                messagebox.showinfo("Info", "Aktivnost označena kao važna")
        except Exception as e:
            self.log_error(f"Greška pri označavanju: {e}")
            messagebox.showerror("Greška", f"Greška pri označavanju: {e}") 