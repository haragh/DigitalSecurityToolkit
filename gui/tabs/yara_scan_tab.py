#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YARA Scan Tab - Skeniranje zlonamjernog softvera
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import yara
from datetime import datetime

from utils.logger import LoggerMixin
from modules.yara_scanner import YaraScanner

class YaraScanTab(ttk.Frame, LoggerMixin):
    """Tab za YARA skeniranje"""
    
    def __init__(self, parent, config, logger):
        ttk.Frame.__init__(self, parent)
        LoggerMixin.__init__(self, "YaraScanTab")
        
        self.config = config
        self.logger = logger
        self.scanner = YaraScanner(config, logger)
        
        self.setup_ui()
        self.log_info("YARA Scan tab inicijalizovan")
    
    def setup_ui(self):
        """Postavljanje korisničkog interfejsa"""
        # Glavni frame
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Kontrole
        self.setup_controls(main_frame)
        
        # Rezultati
        self.setup_results(main_frame)
        
        # Progress
        self.setup_progress(main_frame)
    
    def setup_controls(self, parent):
        """Postavljanje kontrolnih elemenata"""
        controls_frame = ttk.LabelFrame(parent, text="Kontrole", padding=10)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Izbor direktorijuma/fajla
        target_frame = ttk.Frame(controls_frame)
        target_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(target_frame, text="Cilj:").pack(side=tk.LEFT)
        self.target_var = tk.StringVar()
        target_entry = ttk.Entry(target_frame, textvariable=self.target_var, width=40)
        target_entry.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(target_frame, text="Odaberi fajl", command=self.select_file).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(target_frame, text="Odaberi direktorij", command=self.select_directory).pack(side=tk.LEFT, padx=(5, 0))
        
        # YARA pravila
        rules_frame = ttk.Frame(controls_frame)
        rules_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(rules_frame, text="YARA pravila:").pack(side=tk.LEFT)
        self.rules_var = tk.StringVar(value="rules")
        rules_entry = ttk.Entry(rules_frame, textvariable=self.rules_var, width=40)
        rules_entry.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(rules_frame, text="Odaberi", command=self.select_rules_dir).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(rules_frame, text="Učitaj sva", command=self.load_all_rules).pack(side=tk.LEFT, padx=(5, 0))
        
        # Opcije skeniranja
        options_frame = ttk.Frame(controls_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Rekurzivno skeniranje", variable=self.recursive_var).pack(side=tk.LEFT)
        
        self.scan_archives_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Skeniraj arhive", variable=self.scan_archives_var).pack(side=tk.LEFT, padx=(20, 0))
        
        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Detaljni izvještaj", variable=self.verbose_var).pack(side=tk.LEFT, padx=(20, 0))
        
        # Maksimalna veličina
        size_frame = ttk.Frame(controls_frame)
        size_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(size_frame, text="Maks. veličina fajla (MB):").pack(side=tk.LEFT)
        self.max_size_var = tk.IntVar(value=50)
        size_spin = ttk.Spinbox(size_frame, from_=1, to=1000, textvariable=self.max_size_var, width=10)
        size_spin.pack(side=tk.LEFT, padx=(10, 0))
        
        # Dugmad
        button_frame = ttk.Frame(controls_frame)
        button_frame.pack(fill=tk.X)
        
        self.scan_button = ttk.Button(button_frame, text="Pokreni skeniranje", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Zaustavi", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="Očisti rezultate", command=self.clear_results).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Sačuvaj rezultate", command=self.save_results).pack(side=tk.LEFT)
    
    def setup_results(self, parent):
        """Postavljanje prikaza rezultata"""
        results_frame = ttk.LabelFrame(parent, text="Rezultati skeniranja", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Treeview za rezultate
        columns = ('Fajl', 'Pravilo', 'Nivo Opasnosti', 'Detalji', 'Status')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        # Postavljanje kolona
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Context menu
        self.setup_context_menu()
        
        # Statistika
        self.setup_statistics(results_frame)
    
    def setup_statistics(self, parent):
        """Postavljanje statistike"""
        stats_frame = ttk.Frame(parent)
        stats_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.stats_label = ttk.Label(stats_frame, text="Statistika: 0 fajlova skenirano, 0 pronađeno")
        self.stats_label.pack(side=tk.LEFT)
    
    def setup_progress(self, parent):
        """Postavljanje progress bara"""
        progress_frame = ttk.Frame(parent)
        progress_frame.pack(fill=tk.X)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, mode='determinate')
        self.progress_bar.pack(fill=tk.X, side=tk.LEFT, expand=True)
        
        self.progress_label = ttk.Label(progress_frame, text="Spremno")
        self.progress_label.pack(side=tk.RIGHT, padx=(10, 0))
    
    def setup_context_menu(self):
        """Postavljanje context menija"""
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Otvori fajl", command=self.open_file)
        self.context_menu.add_command(label="Otvori direktorij", command=self.open_directory)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Kopiraj putanju", command=self.copy_path)
        self.context_menu.add_command(label="Kopiraj rezultat", command=self.copy_result)
        
        self.results_tree.bind("<Button-3>", self.show_context_menu)
        self.results_tree.bind("<Double-1>", self.open_file)
    
    def select_file(self):
        """Odabir fajla za skeniranje"""
        file_path = filedialog.askopenfilename(title="Odaberi fajl za skeniranje")
        if file_path:
            self.target_var.set(file_path)
    
    def select_directory(self):
        """Odabir direktorijuma za skeniranje"""
        directory = filedialog.askdirectory(title="Odaberi direktorijum za skeniranje")
        if directory:
            self.target_var.set(directory)
    
    def select_rules_dir(self):
        """Odabir direktorijuma sa YARA pravilima"""
        directory = filedialog.askdirectory(title="Odaberi direktorijum sa YARA pravilima")
        if directory:
            self.rules_var.set(directory)
    
    def load_all_rules(self):
        """Učitavanje svih YARA pravila"""
        try:
            rules_dir = self.rules_var.get()
            if not rules_dir or not os.path.exists(rules_dir):
                messagebox.showerror("Greška", "Odaberite validan direktorijum sa pravilima")
                return
            
            rules_count = self.scanner.load_rules_from_directory(rules_dir)
            messagebox.showinfo("Info", f"Učitano {rules_count} YARA pravila")
            
        except Exception as e:
            self.log_error(f"Greška pri učitavanju pravila: {e}")
            messagebox.showerror("Greška", f"Greška pri učitavanju pravila: {e}")
    
    def start_scan(self):
        """Pokretanje skeniranja"""
        try:
            # Validacija
            if not self.target_var.get():
                messagebox.showerror("Greška", "Odaberite cilj za skeniranje")
                return
            
            if not os.path.exists(self.target_var.get()):
                messagebox.showerror("Greška", "Odabrani cilj ne postoji")
                return
            
            # Postavljanje UI-a
            self.scan_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.progress_var.set(0)
            self.progress_label.config(text="Skeniranje u toku...")
            
            # Pokretanje skeniranja u thread-u
            self.scan_thread = threading.Thread(target=self.run_scan)
            self.scan_thread.daemon = True
            self.scan_thread.start()
            
        except Exception as e:
            self.log_error(f"Greška pri pokretanju skeniranja: {e}")
            messagebox.showerror("Greška", f"Greška pri pokretanju skeniranja: {e}")
            self.reset_ui()
    
    def run_scan(self):
        """Izvršavanje skeniranja"""
        try:
            # Parametri
            target = self.target_var.get()
            rules_dir = self.rules_var.get()
            recursive = self.recursive_var.get()
            scan_archives = self.scan_archives_var.get()
            verbose = self.verbose_var.get()
            max_size = self.max_size_var.get() * 1024 * 1024  # MB u bajtove
            
            # Pokretanje skeniranja
            results = self.scanner.scan_target(
                target, rules_dir, recursive, scan_archives, verbose, max_size,
                progress_callback=self.update_progress
            )
            
            # Prikaz rezultata
            self.display_results(results)
            
        except Exception as e:
            self.log_error(f"Greška pri skeniranju: {e}")
            messagebox.showerror("Greška", f"Greška pri skeniranju: {e}")
        finally:
            self.reset_ui()
    
    def stop_scan(self):
        """Zaustavljanje skeniranja"""
        try:
            self.scanner.stop_scan()
            self.progress_label.config(text="Skeniranje zaustavljeno")
        except Exception as e:
            self.log_error(f"Greška pri zaustavljanju: {e}")
        finally:
            self.reset_ui()
    
    def reset_ui(self):
        """Reset UI-a"""
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_label.config(text="Spremno")
    
    def update_progress(self, progress, message):
        """Ažuriranje progress bara"""
        self.progress_var.set(progress)
        self.progress_label.config(text=message)
        self.update_idletasks()
    
    def display_results(self, results):
        """Prikaz rezultata"""
        # Čišćenje postojećih rezultata
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Dodavanje novih rezultata
        total_files = 0
        detected_files = 0
        
        for result in results:
            self.results_tree.insert('', 'end', values=(
                result['file'],
                result['rule'],
                result['severity'],
                result['details'],
                result['status']
            ))
            
            total_files += 1
            if result['status'] == 'detected':
                detected_files += 1
        
        # Ažuriranje statistike
        self.stats_label.config(text=f"Statistika: {total_files} fajlova skenirano, {detected_files} pronađeno")
        
        self.log_info(f"Prikazano {len(results)} rezultata skeniranja")
    
    def clear_results(self):
        """Čišćenje rezultata"""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.progress_var.set(0)
        self.progress_label.config(text="Spremno")
        self.stats_label.config(text="Statistika: 0 fajlova skenirano, 0 pronađeno")
    
    def save_results(self):
        """Čuvanje rezultata"""
        try:
            file_path = filedialog.asksaveasfilename(
                title="Sačuvaj rezultate",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if file_path:
                results = []
                for item in self.results_tree.get_children():
                    values = self.results_tree.item(item)['values']
                    results.append({
                        'file': values[0],
                        'rule': values[1],
                        'severity': values[2],
                        'details': values[3],
                        'status': values[4]
                    })
                
                self.scanner.save_results(results, file_path)
                messagebox.showinfo("Info", f"Rezultati sačuvani u {file_path}")
                
        except Exception as e:
            self.log_error(f"Greška pri čuvanju rezultata: {e}")
            messagebox.showerror("Greška", f"Greška pri čuvanju rezultata: {e}")
    
    def show_context_menu(self, event):
        """Prikaz context menija"""
        try:
            item = self.results_tree.identify_row(event.y)
            if item:
                self.results_tree.selection_set(item)
                self.context_menu.post(event.x_root, event.y_root)
        except Exception as e:
            self.log_error(f"Greška pri prikazu context menija: {e}")
    
    def open_file(self, event=None):
        """Otvaranje fajla"""
        try:
            selection = self.results_tree.selection()
            if selection:
                item = self.results_tree.item(selection[0])
                file_path = item['values'][0]  # Fajl je u 1. koloni
                
                if os.path.exists(file_path):
                    os.startfile(file_path)  # Windows
                else:
                    messagebox.showwarning("Upozorenje", "Fajl ne postoji")
        except Exception as e:
            self.log_error(f"Greška pri otvaranju fajla: {e}")
            messagebox.showerror("Greška", f"Greška pri otvaranju fajla: {e}")
    
    def open_directory(self):
        """Otvaranje direktorijuma"""
        try:
            selection = self.results_tree.selection()
            if selection:
                item = self.results_tree.item(selection[0])
                file_path = item['values'][0]
                directory = os.path.dirname(file_path)
                
                if os.path.exists(directory):
                    os.startfile(directory)  # Windows
                else:
                    messagebox.showwarning("Upozorenje", "Direktorijum ne postoji")
        except Exception as e:
            self.log_error(f"Greška pri otvaranju direktorijuma: {e}")
            messagebox.showerror("Greška", f"Greška pri otvaranju direktorijuma: {e}")
    
    def copy_path(self):
        """Kopiranje putanje u clipboard"""
        try:
            selection = self.results_tree.selection()
            if selection:
                item = self.results_tree.item(selection[0])
                file_path = item['values'][0]
                
                self.clipboard_clear()
                self.clipboard_append(file_path)
                messagebox.showinfo("Info", "Putanja kopirana u clipboard")
        except Exception as e:
            self.log_error(f"Greška pri kopiranju putanje: {e}")
            messagebox.showerror("Greška", f"Greška pri kopiranju putanje: {e}")
    
    def copy_result(self):
        """Kopiranje rezultata u clipboard"""
        try:
            selection = self.results_tree.selection()
            if selection:
                item = self.results_tree.item(selection[0])
                values = item['values']
                result_text = f"Fajl: {values[0]}\nPravilo: {values[1]}\nSevernost: {values[2]}\nDetalji: {values[3]}"
                
                self.clipboard_clear()
                self.clipboard_append(result_text)
                messagebox.showinfo("Info", "Rezultat kopiran u clipboard")
        except Exception as e:
            self.log_error(f"Greška pri kopiranju rezultata: {e}")
            messagebox.showerror("Greška", f"Greška pri kopiranju rezultata: {e}") 