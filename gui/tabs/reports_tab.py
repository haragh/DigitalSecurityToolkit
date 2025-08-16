#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reports Tab - Generator izvještaja
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import json
from datetime import datetime

from utils.logger import LoggerMixin
from modules.report_generator import ReportGenerator

class ReportsTab(ttk.Frame, LoggerMixin):
    """Tab za generisanje izvještaja"""
    
    def __init__(self, parent, config, logger):
        ttk.Frame.__init__(self, parent)
        LoggerMixin.__init__(self, "ReportsTab")
        
        self.config = config
        self.logger = logger
        self.report_generator = ReportGenerator(config, logger)
        
        self.setup_ui()
        self.log_info("Reports tab inicijalizovan")
    
    def setup_ui(self):
        """Postavljanje korisničkog interfejsa"""
        # Glavni frame
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Kontrole
        self.setup_controls(main_frame)
        
        # Izvještaji
        self.setup_reports(main_frame)
        
        # Progress
        self.setup_progress(main_frame)
    
    def setup_controls(self, parent):
        """Postavljanje kontrolnih elemenata"""
        controls_frame = ttk.LabelFrame(parent, text="Kontrole", padding=10)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Tip izvještaja
        report_type_frame = ttk.Frame(controls_frame)
        report_type_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(report_type_frame, text="Tip izvještaja:").pack(side=tk.LEFT)
        
        self.report_type_var = tk.StringVar(value="comprehensive")
        ttk.Radiobutton(report_type_frame, text="Sveobuhvatan", variable=self.report_type_var, value="comprehensive").pack(side=tk.LEFT, padx=(10, 0))
        ttk.Radiobutton(report_type_frame, text="Sažetak", variable=self.report_type_var, value="summary").pack(side=tk.LEFT, padx=(10, 0))
        ttk.Radiobutton(report_type_frame, text="Detaljan", variable=self.report_type_var, value="detailed").pack(side=tk.LEFT, padx=(10, 0))
        
        # Format izvještaja
        format_frame = ttk.Frame(controls_frame)
        format_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(format_frame, text="Format:").pack(side=tk.LEFT)
        
        self.format_var = tk.StringVar(value="pdf")
        ttk.Radiobutton(format_frame, text="PDF", variable=self.format_var, value="pdf").pack(side=tk.LEFT, padx=(10, 0))
        ttk.Radiobutton(format_frame, text="HTML", variable=self.format_var, value="html").pack(side=tk.LEFT, padx=(10, 0))
        ttk.Radiobutton(format_frame, text="JSON", variable=self.format_var, value="json").pack(side=tk.LEFT, padx=(10, 0))
        
        # Opcije
        options_frame = ttk.Frame(controls_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.include_screenshots_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Uključi screenshot-ove", variable=self.include_screenshots_var).pack(side=tk.LEFT)
        
        self.include_charts_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Uključi grafikone", variable=self.include_charts_var).pack(side=tk.LEFT, padx=(20, 0))
        
        self.include_recommendations_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Uključi preporuke", variable=self.include_recommendations_var).pack(side=tk.LEFT, padx=(20, 0))
        
        # Izbor podataka
        data_frame = ttk.Frame(controls_frame)
        data_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(data_frame, text="Podaci za uključivanje:").pack(side=tk.LEFT)
        
        self.include_file_recovery_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(data_frame, text="Oporavak podataka", variable=self.include_file_recovery_var).pack(side=tk.LEFT, padx=(10, 0))
        
        self.include_yara_scan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(data_frame, text="YARA skeniranje", variable=self.include_yara_scan_var).pack(side=tk.LEFT, padx=(10, 0))
        
        self.include_integrity_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(data_frame, text="Provjera integriteta", variable=self.include_integrity_var).pack(side=tk.LEFT, padx=(10, 0))
        
        self.include_timeline_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(data_frame, text="Vremenska linija", variable=self.include_timeline_var).pack(side=tk.LEFT, padx=(10, 0))
        
        self.include_monitoring_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(data_frame, text="Nadzor sistema", variable=self.include_monitoring_var).pack(side=tk.LEFT, padx=(10, 0))
        
        # Output direktorijum
        output_frame = ttk.Frame(controls_frame)
        output_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(output_frame, text="Output direktorij:").pack(side=tk.LEFT)
        self.output_var = tk.StringVar(value="reports")
        output_entry = ttk.Entry(output_frame, textvariable=self.output_var, width=40)
        output_entry.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(output_frame, text="Odaberi", command=self.select_output_dir).pack(side=tk.LEFT, padx=(10, 0))
        
        # Dugmad
        button_frame = ttk.Frame(controls_frame)
        button_frame.pack(fill=tk.X)
        
        self.generate_button = ttk.Button(button_frame, text="Generiši izvještaj", command=self.start_generation)
        self.generate_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Zaustavi", command=self.stop_generation, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="Otvori direktorij", command=self.open_output_dir).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Očisti listu", command=self.clear_reports).pack(side=tk.LEFT)
    
    def setup_reports(self, parent):
        """Postavljanje prikaza izvještaja"""
        reports_frame = ttk.LabelFrame(parent, text="Generisani izvještaji", padding=10)
        reports_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Treeview za izvještaje
        columns = ('Datum', 'Naziv', 'Format', 'Veličina', 'Status')
        self.reports_tree = ttk.Treeview(reports_frame, columns=columns, show='headings', height=10)
        
        # Postavljanje kolona
        for col in columns:
            self.reports_tree.heading(col, text=col)
            if col == 'Datum':
                self.reports_tree.column(col, width=150)
            elif col == 'Naziv':
                self.reports_tree.column(col, width=200)
            elif col == 'Format':
                self.reports_tree.column(col, width=80)
            elif col == 'Veličina':
                self.reports_tree.column(col, width=100)
            else:
                self.reports_tree.column(col, width=100)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(reports_frame, orient=tk.VERTICAL, command=self.reports_tree.yview)
        self.reports_tree.configure(yscrollcommand=scrollbar.set)
        
        self.reports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Context menu
        self.setup_context_menu()
        
        # Učitavanje postojećih izvještaja
        self.load_existing_reports()
    
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
        self.context_menu.add_command(label="Otvori izvještaj", command=self.open_report)
        self.context_menu.add_command(label="Otvori direktorij", command=self.open_report_directory)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Kopiraj putanju", command=self.copy_path)
        self.context_menu.add_command(label="Preimenuj", command=self.rename_report)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Obriši", command=self.delete_report)
        
        self.reports_tree.bind("<Button-3>", self.show_context_menu)
        self.reports_tree.bind("<Double-1>", self.open_report)
    
    def select_output_dir(self):
        """Odabir output direktorijuma"""
        directory = filedialog.askdirectory(title="Odaberi output direktorij")
        if directory:
            self.output_var.set(directory)
    
    def start_generation(self):
        """Pokretanje generisanja izvještaja"""
        try:
            # Validacija
            if not self.output_var.get():
                messagebox.showerror("Greška", "Odaberite output direktorij")
                return
            
            # Postavljanje UI-a
            self.generate_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.progress_var.set(0)
            self.progress_label.config(text="Generisanje izvještaja...")
            
            # Pokretanje generisanja u thread-u
            self.generation_thread = threading.Thread(target=self.run_generation)
            self.generation_thread.daemon = True
            self.generation_thread.start()
            
        except Exception as e:
            self.log_error(f"Greška pri pokretanju generisanja: {e}")
            messagebox.showerror("Greška", f"Greška pri pokretanju generisanja: {e}")
            self.reset_ui()
    
    def run_generation(self):
        """Izvršavanje generisanja izvještaja"""
        try:
            # Parametri
            report_type = self.report_type_var.get()
            output_format = self.format_var.get()
            output_dir = self.output_var.get()
            
            # Opcije
            options = {
                'include_screenshots': self.include_screenshots_var.get(),
                'include_charts': self.include_charts_var.get(),
                'include_recommendations': self.include_recommendations_var.get()
            }
            
            # Podaci za uključivanje
            data_sources = []
            if self.include_file_recovery_var.get():
                data_sources.append('file_recovery')
            if self.include_yara_scan_var.get():
                data_sources.append('yara_scan')
            if self.include_integrity_var.get():
                data_sources.append('integrity')
            if self.include_timeline_var.get():
                data_sources.append('timeline')
            if self.include_monitoring_var.get():
                data_sources.append('monitoring')
            
            # Generisanje izvještaja
            report_path = self.report_generator.generate_report(
                report_type, output_format, output_dir, options, data_sources,
                progress_callback=self.update_progress
            )
            
            # Dodavanje u listu
            if report_path:
                self.add_report_to_list(report_path)
                messagebox.showinfo("Info", f"Izvještaj generisan: {report_path}")
            
        except Exception as e:
            self.log_error(f"Greška pri generisanju: {e}")
            messagebox.showerror("Greška", f"Greška pri generisanju: {e}")
        finally:
            self.reset_ui()
    
    def stop_generation(self):
        """Zaustavljanje generisanja"""
        try:
            self.report_generator.stop_generation()
            self.progress_label.config(text="Generisanje zaustavljeno")
        except Exception as e:
            self.log_error(f"Greška pri zaustavljanju: {e}")
        finally:
            self.reset_ui()
    
    def reset_ui(self):
        """Reset UI-a"""
        self.generate_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_label.config(text="Spremno")
    
    def update_progress(self, progress, message):
        """Ažuriranje progress bara"""
        self.progress_var.set(progress)
        self.progress_label.config(text=message)
        self.update_idletasks()
    
    def load_existing_reports(self):
        """Učitavanje postojećih izvještaja"""
        try:
            output_dir = self.output_var.get()
            if not os.path.exists(output_dir):
                return
            
            for file in os.listdir(output_dir):
                if file.endswith(('.pdf', '.html', '.json')):
                    file_path = os.path.join(output_dir, file)
                    self.add_report_to_list(file_path)
                    
        except Exception as e:
            self.log_error(f"Greška pri učitavanju izvještaja: {e}")
    
    def add_report_to_list(self, file_path):
        """Dodavanje izvještaja u listu"""
        try:
            # Informacije o fajlu
            stat = os.stat(file_path)
            file_size = stat.st_size
            file_date = datetime.fromtimestamp(stat.st_mtime)
            
            # Formatiranje veličine
            if file_size < 1024:
                size_str = f"{file_size} B"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size / 1024:.1f} KB"
            else:
                size_str = f"{file_size / (1024 * 1024):.1f} MB"
            
            # Format
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext == '.pdf':
                format_str = 'PDF'
            elif file_ext == '.html':
                format_str = 'HTML'
            elif file_ext == '.json':
                format_str = 'JSON'
            else:
                format_str = 'NEPOZNATO'
            
            # Dodavanje u treeview
            self.reports_tree.insert('', 0, values=(
                file_date.strftime("%Y-%m-%d %H:%M"),
                os.path.basename(file_path),
                format_str,
                size_str,
                'OK'
            ))
            
        except Exception as e:
            self.log_error(f"Greška pri dodavanju izvještaja: {e}")
    
    def clear_reports(self):
        """Čišćenje liste izvještaja"""
        for item in self.reports_tree.get_children():
            self.reports_tree.delete(item)
    
    def open_output_dir(self):
        """Otvaranje output direktorija"""
        try:
            output_dir = self.output_var.get()
            if os.path.exists(output_dir):
                os.startfile(output_dir)  # Windows
            else:
                messagebox.showwarning("Upozorenje", "Output direktorij ne postoji")
        except Exception as e:
            self.log_error(f"Greška pri otvaranju direktorija: {e}")
            messagebox.showerror("Greška", f"Greška pri otvaranju direktorija: {e}")
    
    def show_context_menu(self, event):
        """Prikaz context menija"""
        try:
            item = self.reports_tree.identify_row(event.y)
            if item:
                self.reports_tree.selection_set(item)
                self.context_menu.post(event.x_root, event.y_root)
        except Exception as e:
            self.log_error(f"Greška pri prikazu context menija: {e}")
    
    def open_report(self, event=None):
        """Otvaranje izvještaja"""
        try:
            selection = self.reports_tree.selection()
            if selection:
                item = self.reports_tree.item(selection[0])
                report_name = item['values'][1]
                output_dir = self.output_var.get()
                report_path = os.path.join(output_dir, report_name)
                
                if os.path.exists(report_path):
                    os.startfile(report_path)  # Windows
                else:
                    messagebox.showwarning("Upozorenje", "Izvještaj ne postoji")
        except Exception as e:
            self.log_error(f"Greška pri otvaranju izvještaja: {e}")
            messagebox.showerror("Greška", f"Greška pri otvaranju izvještaja: {e}")
    
    def open_report_directory(self):
        """Otvaranje direktorija izvještaja"""
        try:
            output_dir = self.output_var.get()
            if os.path.exists(output_dir):
                os.startfile(output_dir)  # Windows
            else:
                messagebox.showwarning("Upozorenje", "Direktorij ne postoji")
        except Exception as e:
            self.log_error(f"Greška pri otvaranju direktorija: {e}")
            messagebox.showerror("Greška", f"Greška pri otvaranju direktorija: {e}")
    
    def copy_path(self):
        """Kopiranje putanje u clipboard"""
        try:
            selection = self.reports_tree.selection()
            if selection:
                item = self.reports_tree.item(selection[0])
                report_name = item['values'][1]
                output_dir = self.output_var.get()
                report_path = os.path.join(output_dir, report_name)
                
                self.clipboard_clear()
                self.clipboard_append(report_path)
                messagebox.showinfo("Info", "Putanja kopirana u clipboard")
        except Exception as e:
            self.log_error(f"Greška pri kopiranju putanje: {e}")
            messagebox.showerror("Greška", f"Greška pri kopiranju putanje: {e}")
    
    def rename_report(self):
        """Preimenovanje izvještaja"""
        try:
            selection = self.reports_tree.selection()
            if selection:
                item = self.reports_tree.item(selection[0])
                old_name = item['values'][1]
                output_dir = self.output_var.get()
                old_path = os.path.join(output_dir, old_name)
                
                # Dialog za novo ime
                new_name = tk.simpledialog.askstring("Preimenuj", "Novo ime:", initialvalue=old_name)
                if new_name and new_name != old_name:
                    new_path = os.path.join(output_dir, new_name)
                    
                    if os.path.exists(new_path):
                        messagebox.showerror("Greška", "Fajl sa tim imenom već postoji")
                        return
                    
                    os.rename(old_path, new_path)
                    
                    # Ažuriranje u listi
                    self.reports_tree.delete(selection[0])
                    self.add_report_to_list(new_path)
                    
                    messagebox.showinfo("Info", "Izvještaj preimenovan")
                    
        except Exception as e:
            self.log_error(f"Greška pri preimenovanju: {e}")
            messagebox.showerror("Greška", f"Greška pri preimenovanju: {e}")
    
    def delete_report(self):
        """Brisanje izvještaja"""
        try:
            selection = self.reports_tree.selection()
            if selection:
                item = self.reports_tree.item(selection[0])
                report_name = item['values'][1]
                
                # Potvrda brisanja
                if messagebox.askyesno("Potvrda", f"Da li ste sigurni da želite obrisati {report_name}?"):
                    output_dir = self.output_var.get()
                    report_path = os.path.join(output_dir, report_name)
                    
                    if os.path.exists(report_path):
                        os.remove(report_path)
                        self.reports_tree.delete(selection[0])
                        messagebox.showinfo("Info", "Izvještaj obrisan")
                    else:
                        messagebox.showwarning("Upozorenje", "Izvještaj ne postoji")
                        
        except Exception as e:
            self.log_error(f"Greška pri brisanju: {e}")
            messagebox.showerror("Greška", f"Greška pri brisanju: {e}") 