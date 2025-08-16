#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Timeline Tab - Vremenska linija aktivnosti
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import json
from datetime import datetime, timedelta

from utils.logger import LoggerMixin
from modules.timeline_analyzer import TimelineAnalyzer

class TimelineTab(ttk.Frame, LoggerMixin):
    """Tab za vremensku liniju aktivnosti"""
    
    def __init__(self, parent, config, logger):
        ttk.Frame.__init__(self, parent)
        LoggerMixin.__init__(self, "TimelineTab")
        
        self.config = config
        self.logger = logger
        self.analyzer = TimelineAnalyzer(config, logger)
        
        self.setup_ui()
        self.log_info("Timeline tab inicijalizovan")
    
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
        
        # Izbor direktorijuma
        target_frame = ttk.Frame(controls_frame)
        target_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(target_frame, text="Direktorij:").pack(side=tk.LEFT)
        self.target_var = tk.StringVar()
        target_entry = ttk.Entry(target_frame, textvariable=self.target_var, width=40)
        target_entry.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(target_frame, text="Odaberi", command=self.select_directory).pack(side=tk.LEFT, padx=(10, 0))
        
        # Vremenski period
        time_frame = ttk.Frame(controls_frame)
        time_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(time_frame, text="Period:").pack(side=tk.LEFT)
        
        self.start_date_var = tk.StringVar()
        start_date_entry = ttk.Entry(time_frame, textvariable=self.start_date_var, width=15)
        start_date_entry.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Label(time_frame, text="do").pack(side=tk.LEFT, padx=(10, 0))
        
        self.end_date_var = tk.StringVar()
        end_date_entry = ttk.Entry(time_frame, textvariable=self.end_date_var, width=15)
        end_date_entry.pack(side=tk.LEFT, padx=(10, 0))
        
        # Postavljanje default datuma (zadnjih 7 dana)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        self.start_date_var.set(start_date.strftime("%Y-%m-%d"))
        self.end_date_var.set(end_date.strftime("%Y-%m-%d"))
        
        # Opcije
        options_frame = ttk.Frame(controls_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.include_deleted_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Uključi obrisane fajlove", variable=self.include_deleted_var).pack(side=tk.LEFT)
        
        self.include_system_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Uključi sistemske fajlove", variable=self.include_system_var).pack(side=tk.LEFT, padx=(20, 0))
        
        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Rekurzivno skeniranje", variable=self.recursive_var).pack(side=tk.LEFT, padx=(20, 0))
        
        # Filtriranje
        filter_frame = ttk.Frame(controls_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(filter_frame, text="Filtri:").pack(side=tk.LEFT)
        
        self.filter_modified_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(filter_frame, text="Modifikovani", variable=self.filter_modified_var).pack(side=tk.LEFT, padx=(10, 0))
        
        self.filter_accessed_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(filter_frame, text="Pristupljeni", variable=self.filter_accessed_var).pack(side=tk.LEFT, padx=(10, 0))
        
        self.filter_created_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(filter_frame, text="Kreirani", variable=self.filter_created_var).pack(side=tk.LEFT, padx=(10, 0))
        
        # Dugmad
        button_frame = ttk.Frame(controls_frame)
        button_frame.pack(fill=tk.X)
        
        self.analyze_button = ttk.Button(button_frame, text="Analiziraj", command=self.start_analysis)
        self.analyze_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Zaustavi", command=self.stop_analysis, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="Očisti rezultate", command=self.clear_results).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Sačuvaj rezultate", command=self.save_results).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Export CSV", command=self.export_csv).pack(side=tk.LEFT)
    
    def setup_results(self, parent):
        """Postavljanje prikaza rezultata"""
        results_frame = ttk.LabelFrame(parent, text="Vremenska linija", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Treeview za rezultate
        columns = ('Fajl', 'Tip', 'Veličina', 'Modifikovan', 'Pristupljen', 'Kreiran', 'Putanja')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        # Postavljanje kolona
        for col in columns:
            self.results_tree.heading(col, text=col)
            if col == 'Fajl':
                self.results_tree.column(col, width=200)
            elif col == 'Tip':
                self.results_tree.column(col, width=80)
            elif col == 'Veličina':
                self.results_tree.column(col, width=100)
            elif col in ('Modifikovan', 'Pristupljen', 'Kreiran'):
                self.results_tree.column(col, width=150)
            else:
                self.results_tree.column(col, width=300)
        
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
        
        self.stats_label = ttk.Label(stats_frame, text="Statistika: 0 aktivnosti pronađeno")
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
        self.context_menu.add_command(label="Kopiraj datum", command=self.copy_date)
        
        self.results_tree.bind("<Button-3>", self.show_context_menu)
        self.results_tree.bind("<Double-1>", self.open_file)
    
    def select_directory(self):
        """Odabir direktorijuma"""
        directory = filedialog.askdirectory(title="Odaberi direktorij za analizu")
        if directory:
            self.target_var.set(directory)
    
    def start_analysis(self):
        """Pokretanje analize"""
        try:
            # Validacija
            if not self.target_var.get():
                messagebox.showerror("Greška", "Odaberite direktorij")
                return
            
            if not os.path.exists(self.target_var.get()):
                messagebox.showerror("Greška", "Odabrani direktorij ne postoji")
                return
            
            # Postavljanje UI-a
            self.analyze_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.progress_var.set(0)
            self.progress_label.config(text="Analiza u toku...")
            
            # Pokretanje analize u thread-u
            self.analysis_thread = threading.Thread(target=self.run_analysis)
            self.analysis_thread.daemon = True
            self.analysis_thread.start()
            
        except Exception as e:
            self.log_error(f"Greška pri pokretanju analize: {e}")
            messagebox.showerror("Greška", f"Greška pri pokretanju analize: {e}")
            self.reset_ui()
    
    def run_analysis(self):
        """Izvršavanje analize"""
        try:
            # Parametri
            directory = self.target_var.get()
            start_date = datetime.strptime(self.start_date_var.get(), "%Y-%m-%d")
            end_date = datetime.strptime(self.end_date_var.get(), "%Y-%m-%d")
            include_deleted = self.include_deleted_var.get()
            include_system = self.include_system_var.get()
            recursive = self.recursive_var.get()
            
            # Filtri
            filters = []
            if self.filter_modified_var.get():
                filters.append('modified')
            if self.filter_accessed_var.get():
                filters.append('accessed')
            if self.filter_created_var.get():
                filters.append('created')
            
            # Pokretanje analize
            results = self.analyzer.analyze_timeline(
                directory, start_date, end_date, include_deleted, 
                include_system, recursive, filters,
                progress_callback=self.update_progress
            )
            
            # Prikaz rezultata
            self.display_results(results)
            
        except Exception as e:
            self.log_error(f"Greška pri analizi: {e}")
            messagebox.showerror("Greška", f"Greška pri analizi: {e}")
        finally:
            self.reset_ui()
    
    def stop_analysis(self):
        """Zaustavljanje analize"""
        try:
            self.analyzer.stop_analysis()
            self.progress_label.config(text="Analiza zaustavljena")
        except Exception as e:
            self.log_error(f"Greška pri zaustavljanju: {e}")
        finally:
            self.reset_ui()
    
    def reset_ui(self):
        """Reset UI-a"""
        self.analyze_button.config(state=tk.NORMAL)
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
        total_activities = 0
        
        for activity in results:
            # Formatiranje veličine
            size = activity.get('size', 0)
            if size:
                if size < 1024:
                    size_str = f"{size} B"
                elif size < 1024 * 1024:
                    size_str = f"{size / 1024:.1f} KB"
                else:
                    size_str = f"{size / (1024 * 1024):.1f} MB"
            else:
                size_str = ''
            
            self.results_tree.insert('', 'end', values=(
                activity.get('filename', ''),
                activity.get('type', ''),
                size_str,
                activity.get('modified', ''),
                activity.get('accessed', ''),
                activity.get('created', ''),
                activity.get('path', '')
            ))
            total_activities += 1
        
        # Ažuriranje statistike
        self.stats_label.config(text=f"Statistika: {total_activities} stavki pronađeno")
        
        self.log_info(f"Prikazano {total_activities} stavki")
    
    def clear_results(self):
        """Čišćenje rezultata"""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.progress_var.set(0)
        self.progress_label.config(text="Spremno")
        self.stats_label.config(text="Statistika: 0 aktivnosti pronađeno")
    
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
                        'timestamp': values[0],
                        'filename': values[1],
                        'action': values[2],
                        'size': values[3],
                        'path': values[4]
                    })
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=4, ensure_ascii=False)
                
                messagebox.showinfo("Info", f"Rezultati sačuvani u {file_path}")
                
        except Exception as e:
            self.log_error(f"Greška pri čuvanju rezultata: {e}")
            messagebox.showerror("Greška", f"Greška pri čuvanju rezultata: {e}")
    
    def export_csv(self):
        """Export rezultata u CSV"""
        try:
            file_path = filedialog.asksaveasfilename(
                title="Export CSV",
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            
            if file_path:
                import csv
                
                with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    
                    # Header
                    writer.writerow(['Datum/Vrijeme', 'Fajl', 'Akcija', 'Veličina', 'Putanja'])
                    
                    # Podaci
                    for item in self.results_tree.get_children():
                        values = self.results_tree.item(item)['values']
                        writer.writerow(values)
                
                messagebox.showinfo("Info", f"CSV exportovan u {file_path}")
                
        except Exception as e:
            self.log_error(f"Greška pri exportu CSV: {e}")
            messagebox.showerror("Greška", f"Greška pri exportu CSV: {e}")
    
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
                file_path = item['values'][6]  # Putanja je u 7. koloni
                
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
                file_path = item['values'][6]
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
                file_path = item['values'][6]
                
                self.clipboard_clear()
                self.clipboard_append(file_path)
                messagebox.showinfo("Info", "Putanja kopirana u clipboard")
        except Exception as e:
            self.log_error(f"Greška pri kopiranju putanje: {e}")
            messagebox.showerror("Greška", f"Greška pri kopiranju putanje: {e}")
    
    def copy_date(self):
        """Kopiranje datuma u clipboard"""
        try:
            selection = self.results_tree.selection()
            if selection:
                item = self.results_tree.item(selection[0])
                date_time = item['values'][0]
                
                self.clipboard_clear()
                self.clipboard_append(date_time)
                messagebox.showinfo("Info", "Datum kopiran u clipboard")
        except Exception as e:
            self.log_error(f"Greška pri kopiranju datuma: {e}")
            messagebox.showerror("Greška", f"Greška pri kopiranju datuma: {e}") 