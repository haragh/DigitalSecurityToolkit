#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integrity Tab - Provjera integriteta fajlova
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import json
from datetime import datetime

from utils.logger import LoggerMixin
from utils.hash_utils import HashUtils

class IntegrityTab(ttk.Frame, LoggerMixin):
    """Tab za provjeru integriteta"""
    
    def __init__(self, parent, config, logger):
        ttk.Frame.__init__(self, parent)
        LoggerMixin.__init__(self, "IntegrityTab")
        
        self.config = config
        self.logger = logger
        self.hash_utils = HashUtils()
        
        self.setup_ui()
        self.log_info("Integrity tab inicijalizovan")
    
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
        
        # Hash algoritmi
        algorithms_frame = ttk.Frame(controls_frame)
        algorithms_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(algorithms_frame, text="Hash algoritmi:").pack(side=tk.LEFT)
        
        self.md5_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(algorithms_frame, text="MD5", variable=self.md5_var).pack(side=tk.LEFT, padx=(10, 0))
        
        self.sha1_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(algorithms_frame, text="SHA1", variable=self.sha1_var).pack(side=tk.LEFT, padx=(10, 0))
        
        self.sha256_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(algorithms_frame, text="SHA256", variable=self.sha256_var).pack(side=tk.LEFT, padx=(10, 0))
        
        self.sha512_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(algorithms_frame, text="SHA512", variable=self.sha512_var).pack(side=tk.LEFT, padx=(10, 0))
        
        # Opcije
        options_frame = ttk.Frame(controls_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.save_hashes_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Sačuvaj hash-ove", variable=self.save_hashes_var).pack(side=tk.LEFT)
        
        self.verify_existing_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Provjeri postojeće", variable=self.verify_existing_var).pack(side=tk.LEFT, padx=(20, 0))
        
        # Hash baza
        database_frame = ttk.Frame(controls_frame)
        database_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(database_frame, text="Hash baza:").pack(side=tk.LEFT)
        self.database_var = tk.StringVar(value="data/file_hashes.json")
        database_entry = ttk.Entry(database_frame, textvariable=self.database_var, width=40)
        database_entry.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(database_frame, text="Odaberi", command=self.select_database).pack(side=tk.LEFT, padx=(10, 0))
        
        # Dugmad
        button_frame = ttk.Frame(controls_frame)
        button_frame.pack(fill=tk.X)
        
        self.calculate_button = ttk.Button(button_frame, text="Izračunaj hash-ove", command=self.start_calculation)
        self.calculate_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.verify_button = ttk.Button(button_frame, text="Provjeri integritet", command=self.start_verification)
        self.verify_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Zaustavi", command=self.stop_process, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="Očisti rezultate", command=self.clear_results).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Sačuvaj rezultate", command=self.save_results).pack(side=tk.LEFT)
    
    def setup_results(self, parent):
        """Postavljanje prikaza rezultata"""
        results_frame = ttk.LabelFrame(parent, text="Rezultati", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Treeview za rezultate
        columns = ('Fajl', 'MD5', 'SHA1', 'SHA256', 'Status')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        # Postavljanje kolona
        for col in columns:
            self.results_tree.heading(col, text=col)
            if col == 'Fajl':
                self.results_tree.column(col, width=300)
            elif col == 'Status':
                self.results_tree.column(col, width=100)
            else:
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
        
        self.stats_label = ttk.Label(stats_frame, text="Statistika: 0 fajlova obrađeno")
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
        self.context_menu.add_command(label="Kopiraj hash", command=self.copy_hash)
        
        self.results_tree.bind("<Button-3>", self.show_context_menu)
        self.results_tree.bind("<Double-1>", self.open_file)
    
    def select_file(self):
        """Odabir fajla"""
        file_path = filedialog.askopenfilename(title="Odaberi fajl")
        if file_path:
            self.target_var.set(file_path)
    
    def select_directory(self):
        """Odabir direktorijuma"""
        directory = filedialog.askdirectory(title="Odaberi direktorij")
        if directory:
            self.target_var.set(directory)
    
    def select_database(self):
        """Odabir hash baze podataka"""
        file_path = filedialog.askopenfilename(
            title="Odaberi hash bazu podataka",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            self.database_var.set(file_path)
    
    def get_selected_algorithms(self):
        """Dobijanje odabranih hash algoritama"""
        algorithms = []
        if self.md5_var.get():
            algorithms.append('md5')
        if self.sha1_var.get():
            algorithms.append('sha1')
        if self.sha256_var.get():
            algorithms.append('sha256')
        if self.sha512_var.get():
            algorithms.append('sha512')
        return algorithms
    
    def start_calculation(self):
        """Pokretanje izračunavanja hash-ova"""
        try:
            # Validacija
            if not self.target_var.get():
                messagebox.showerror("Greška", "Odaberite cilj")
                return
            
            if not os.path.exists(self.target_var.get()):
                messagebox.showerror("Greška", "Odabrani cilj ne postoji")
                return
            
            algorithms = self.get_selected_algorithms()
            if not algorithms:
                messagebox.showerror("Greška", "Odaberite bar jedan hash algoritam")
                return
            
            # Postavljanje UI-a
            self.calculate_button.config(state=tk.DISABLED)
            self.verify_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.progress_var.set(0)
            self.progress_label.config(text="Izračunavanje hash-ova...")
            
            # Pokretanje u thread-u
            self.process_thread = threading.Thread(target=self.run_calculation, args=(algorithms,))
            self.process_thread.daemon = True
            self.process_thread.start()
            
        except Exception as e:
            self.log_error(f"Greška pri pokretanju izračunavanja: {e}")
            messagebox.showerror("Greška", f"Greška pri pokretanju izračunavanja: {e}")
            self.reset_ui()
    
    def run_calculation(self, algorithms):
        """Izvršavanje izračunavanja hash-ova"""
        try:
            target = self.target_var.get()
            save_hashes = self.save_hashes_var.get()
            database_file = self.database_var.get()
            
            if os.path.isfile(target):
                # Pojedinačni fajl
                results = self.calculate_single_file(target, algorithms)
            else:
                # Direktorijum
                results = self.calculate_directory(target, algorithms)
            
            # Prikaz rezultata
            self.display_results(results)
            
            # Čuvanje hash-ova
            if save_hashes and results:
                self.hash_utils.save_hash_database(results, database_file)
            
        except Exception as e:
            self.log_error(f"Greška pri izračunavanju: {e}")
            messagebox.showerror("Greška", f"Greška pri izračunavanju: {e}")
        finally:
            self.reset_ui()
    
    def calculate_single_file(self, file_path, algorithms):
        """Izračunavanje hash-ova za pojedinačni fajl"""
        results = {
            'directory': os.path.dirname(file_path),
            'timestamp': datetime.now().isoformat(),
            'files': {}
        }
        
        try:
            file_hashes = self.hash_utils.calculate_multiple_hashes(file_path, algorithms)
            if file_hashes:
                results['files'][file_path] = {
                    'hashes': file_hashes,
                    'size': os.path.getsize(file_path),
                    'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                }
        except Exception as e:
            self.log_error(f"Greška pri obradi fajla {file_path}: {e}")
        
        return results
    
    def calculate_directory(self, directory_path, algorithms):
        """Izračunavanje hash-ova za direktorijum"""
        return self.hash_utils.scan_directory_hashes(directory_path, algorithms)
    
    def start_verification(self):
        """Pokretanje provjere integriteta"""
        try:
            # Validacija
            if not self.database_var.get():
                messagebox.showerror("Greška", "Odaberite hash bazu podataka")
                return
            
            if not os.path.exists(self.database_var.get()):
                messagebox.showerror("Greška", "Hash baza podataka ne postoji")
                return
            
            # Postavljanje UI-a
            self.calculate_button.config(state=tk.DISABLED)
            self.verify_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.progress_var.set(0)
            self.progress_label.config(text="Provjera integriteta...")
            
            # Pokretanje u thread-u
            self.process_thread = threading.Thread(target=self.run_verification)
            self.process_thread.daemon = True
            self.process_thread.start()
            
        except Exception as e:
            self.log_error(f"Greška pri pokretanju provjere: {e}")
            messagebox.showerror("Greška", f"Greška pri pokretanju provjere: {e}")
            self.reset_ui()
    
    def run_verification(self):
        """Izvršavanje provjere integriteta"""
        try:
            database_file = self.database_var.get()
            
            # Učitavanje hash baze
            hash_database = self.hash_utils.load_hash_database(database_file)
            if not hash_database or 'files' not in hash_database:
                messagebox.showerror("Greška", "Hash baza podataka je prazna ili neispravna")
                return
            
            # Provjera svih fajlova
            verification_results = []
            total_files = len(hash_database['files'])
            processed_files = 0
            
            for file_path, file_data in hash_database['files'].items():
                if os.path.exists(file_path):
                    expected_hashes = file_data.get('hashes', {})
                    verification_result = self.hash_utils.verify_file_integrity(file_path, expected_hashes)
                    verification_results.append(verification_result)
                else:
                    verification_results.append({
                        'file_path': file_path,
                        'overall_status': 'missing',
                        'error': 'Fajl ne postoji'
                    })
                
                processed_files += 1
                progress = (processed_files / total_files) * 100
                self.update_progress(progress, f"Provjera {processed_files}/{total_files}")
            
            # Prikaz rezultata
            self.display_verification_results(verification_results)
            
        except Exception as e:
            self.log_error(f"Greška pri provjeri: {e}")
            messagebox.showerror("Greška", f"Greška pri provjeri: {e}")
        finally:
            self.reset_ui()
    
    def stop_process(self):
        """Zaustavljanje procesa"""
        self.progress_label.config(text="Proces zaustavljen")
        self.reset_ui()
    
    def reset_ui(self):
        """Reset UI-a"""
        self.calculate_button.config(state=tk.NORMAL)
        self.verify_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_label.config(text="Spremno")
    
    def update_progress(self, progress, message):
        """Ažuriranje progress bara"""
        self.progress_var.set(progress)
        self.progress_label.config(text=message)
        self.update_idletasks()
    
    def display_results(self, results):
        """Prikaz rezultata izračunavanja"""
        # Čišćenje postojećih rezultata
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Dodavanje novih rezultata
        total_files = 0
        
        for file_path, file_data in results.get('files', {}).items():
            hashes = file_data.get('hashes', {})
            
            self.results_tree.insert('', 'end', values=(
                file_path,
                hashes.get('md5', ''),
                hashes.get('sha1', ''),
                hashes.get('sha256', ''),
                'OK'
            ))
            total_files += 1
        
        # Ažuriranje statistike
        self.stats_label.config(text=f"Statistika: {total_files} fajlova obrađeno")
        
        self.log_info(f"Prikazano {total_files} rezultata")
    
    def display_verification_results(self, results):
        """Prikaz rezultata provjere"""
        # Čišćenje postojećih rezultata
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Dodavanje novih rezultata
        total_files = 0
        valid_files = 0
        
        for result in results:
            file_path = result['file_path']
            status = result['overall_status']
            
            if status == 'valid':
                valid_files += 1
                status_text = 'OK'
            elif status == 'invalid':
                status_text = 'NARUŠEN'
            elif status == 'missing':
                status_text = 'NEPOSTOJI'
            else:
                status_text = 'GREŠKA'
            
            # Dobijanje hash-ova
            hashes = {}
            if 'verification_results' in result:
                for alg, verif_result in result['verification_results'].items():
                    hashes[alg] = verif_result.get('current', '')
            
            self.results_tree.insert('', 'end', values=(
                file_path,
                hashes.get('md5', ''),
                hashes.get('sha1', ''),
                hashes.get('sha256', ''),
                status_text
            ))
            total_files += 1
        
        # Ažuriranje statistike
        self.stats_label.config(text=f"Statistika: {total_files} fajlova provjereno, {valid_files} validno")
        
        self.log_info(f"Prikazano {total_files} rezultata provjere")
    
    def clear_results(self):
        """Čišćenje rezultata"""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.progress_var.set(0)
        self.progress_label.config(text="Spremno")
        self.stats_label.config(text="Statistika: 0 fajlova obrađeno")
    
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
                        'md5': values[1],
                        'sha1': values[2],
                        'sha256': values[3],
                        'status': values[4]
                    })
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=4, ensure_ascii=False)
                
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
                file_path = item['values'][0]
                
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
                    messagebox.showwarning("Upozorenje", "Direktorij ne postoji")
        except Exception as e:
            self.log_error(f"Greška pri otvaranju direktorija: {e}")
            messagebox.showerror("Greška", f"Greška pri otvaranju direktorija: {e}")
    
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
    
    def copy_hash(self):
        """Kopiranje hash-a u clipboard"""
        try:
            selection = self.results_tree.selection()
            if selection:
                item = self.results_tree.item(selection[0])
                values = item['values']
                
                # Kopiranje SHA256 hash-a (najčešće korišten)
                hash_value = values[3]  # SHA256 je u 4. koloni
                if hash_value:
                    self.clipboard_clear()
                    self.clipboard_append(hash_value)
                    messagebox.showinfo("Info", "Hash kopiran u clipboard")
                else:
                    messagebox.showwarning("Upozorenje", "Hash nije dostupan")
        except Exception as e:
            self.log_error(f"Greška pri kopiranju hash-a: {e}")
            messagebox.showerror("Greška", f"Greška pri kopiranju hash-a: {e}") 