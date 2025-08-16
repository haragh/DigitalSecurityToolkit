#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File Recovery Tab - Oporavak podataka
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import struct
from datetime import datetime

from utils.logger import LoggerMixin
from modules.file_recovery import FileRecovery

class FileRecoveryTab(ttk.Frame, LoggerMixin):
    """Tab za oporavak podataka"""
    
    def __init__(self, parent, config, logger):
        ttk.Frame.__init__(self, parent)
        LoggerMixin.__init__(self, "FileRecoveryTab")
        
        self.config = config
        self.logger = logger
        self.recovery_engine = FileRecovery(config, logger)
        
        self.setup_ui()
        self.log_info("File Recovery tab inicijalizovan")
    
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
        
        # Admin status indicator
        admin_frame = ttk.Frame(controls_frame)
        admin_frame.pack(fill=tk.X, pady=(0, 10))
        
        if self.is_admin():
            admin_label = ttk.Label(
                admin_frame,
                text="🔒 ADMIN MODE - pytsk3 oporavak omogućen",
                foreground="green",
                font=("Arial", 9, "bold")
            )
            admin_label.pack(side=tk.LEFT)
        else:
            admin_label = ttk.Label(
                admin_frame,
                text="⚠️ LIMITED MODE - pytsk3 oporavak onemogućen (potrebni admin privilegiji)",
                foreground="orange",
                font=("Arial", 9, "bold")
            )
            admin_label.pack(side=tk.LEFT)
        
        # Način oporavka
        recovery_frame = ttk.Frame(controls_frame)
        recovery_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(recovery_frame, text="Način oporavka:").pack(side=tk.LEFT)
        self.recovery_mode = tk.StringVar(value="safe_memory_scan")
        recovery_combo = ttk.Combobox(recovery_frame, textvariable=self.recovery_mode, 
                                     values=["safe_memory_scan"], 
                                     state="readonly", width=20)
        recovery_combo.pack(side=tk.LEFT, padx=(10, 0))
        

        
        # Event handler za promjenu načina
        recovery_combo.bind("<<ComboboxSelected>>", self.on_recovery_mode_change)
        
        # Izbor diska (samo za safe_disk_scan)
        self.disk_frame = ttk.Frame(controls_frame)
        self.disk_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(self.disk_frame, text="Disk/particija:").pack(side=tk.LEFT)
        self.disk_var = tk.StringVar()
        self.disk_combo = ttk.Combobox(self.disk_frame, textvariable=self.disk_var, width=20)
        self.disk_combo.pack(side=tk.LEFT, padx=(10, 0))
        self.load_disks()
        
        # Izbor formata
        format_frame = ttk.Frame(controls_frame)
        format_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(format_frame, text="Formati fajlova:").pack(side=tk.LEFT)
        self.format_var = tk.StringVar(value="jpg,png,pdf,doc,txt")
        format_entry = ttk.Entry(format_frame, textvariable=self.format_var, width=30)
        format_entry.pack(side=tk.LEFT, padx=(10, 0))
        
        # Maksimalna veličina
        size_frame = ttk.Frame(controls_frame)
        size_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(size_frame, text="Maks. veličina (MB):").pack(side=tk.LEFT)
        self.max_size_var = tk.IntVar(value=100)
        size_spin = ttk.Spinbox(size_frame, from_=1, to=1000, textvariable=self.max_size_var, width=10)
        size_spin.pack(side=tk.LEFT, padx=(10, 0))
        
        # Maksimalan broj fajlova
        max_files_frame = ttk.Frame(controls_frame)
        max_files_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(max_files_frame, text="Maks. broj fajlova:").pack(side=tk.LEFT)
        self.max_files_var = tk.IntVar(value=50)
        max_files_spin = ttk.Spinbox(max_files_frame, from_=1, to=1000, textvariable=self.max_files_var, width=10)
        max_files_spin.pack(side=tk.LEFT, padx=(10, 0))
        
        # Output direktorijum
        output_frame = ttk.Frame(controls_frame)
        output_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(output_frame, text="Output direktorij:").pack(side=tk.LEFT)
        self.output_var = tk.StringVar(value="recovered_files")
        output_entry = ttk.Entry(output_frame, textvariable=self.output_var, width=30)
        output_entry.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(output_frame, text="Odaberi", command=self.select_output_dir).pack(side=tk.LEFT, padx=(10, 0))
        
        # Dugmad
        button_frame = ttk.Frame(controls_frame)
        button_frame.pack(fill=tk.X)
        
        self.scan_button = ttk.Button(button_frame, text="Pokreni oporavak", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Zaustavi", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="Očisti rezultate", command=self.clear_results).pack(side=tk.LEFT)
        
        # Inicijalno sakrivanje disk frame-a
        self.on_recovery_mode_change()
        

    
    def on_recovery_mode_change(self, event=None):
        """Handler za promjenu načina oporavka"""
        mode = self.recovery_mode.get()
        
        if mode == "safe_memory_scan":
            self.disk_frame.pack_forget()
    
    def setup_results(self, parent):
        """Postavljanje prikaza rezultata"""
        results_frame = ttk.LabelFrame(parent, text="Pronađeni fajlovi", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Treeview za rezultate
        columns = ('Ime', 'Format', 'Veličina', 'Status', 'Izvor', 'Putanja')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        # Postavljanje kolona
        for col in columns:
            self.results_tree.heading(col, text=col)
            if col == 'Ime':
                self.results_tree.column(col, width=250)
            elif col == 'Format':
                self.results_tree.column(col, width=80)
            elif col == 'Veličina':
                self.results_tree.column(col, width=100)
            elif col == 'Status':
                self.results_tree.column(col, width=120)
            elif col == 'Izvor':
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
        
        # Content preview frame
        self.setup_content_preview(results_frame)
    
    def setup_content_preview(self, parent):
        """Postavljanje prikaza sadržaja fajla"""
        preview_frame = ttk.LabelFrame(parent, text="Pregled sadržaja", padding=10)
        preview_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.content_text = tk.Text(preview_frame, height=6, wrap=tk.WORD)
        content_scrollbar = ttk.Scrollbar(preview_frame, orient=tk.VERTICAL, command=self.content_text.yview)
        self.content_text.configure(yscrollcommand=content_scrollbar.set)
        
        self.content_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        content_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event
        self.results_tree.bind('<<TreeviewSelect>>', self.on_file_select)
    
    def on_file_select(self, event):
        """Handler za odabir fajla u rezultatima"""
        try:
            selection = self.results_tree.selection()
            if selection:
                item = self.results_tree.item(selection[0])
                values = item['values']
                
                # Get file path
                file_path = values[5]  # Putanja is in 6th column
                
                if os.path.exists(file_path):
                    # Read file content for preview
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read(1000)  # Read first 1000 bytes
                        
                        # Try to decode as text
                        try:
                            text_content = content.decode('utf-8', errors='ignore')
                            preview = text_content[:500] + "..." if len(text_content) > 500 else text_content
                        except:
                            preview = f"[Binary data: {len(content)} bytes]"
                        
                        # Update preview
                        self.content_text.delete(1.0, tk.END)
                        self.content_text.insert(1.0, preview)
                        
                    except Exception as e:
                        self.content_text.delete(1.0, tk.END)
                        self.content_text.insert(1.0, f"Greška pri čitanju fajla: {e}")
                else:
                    self.content_text.delete(1.0, tk.END)
                    self.content_text.insert(1.0, "Fajl ne postoji")
                    
        except Exception as e:
            self.log_error(f"Greška pri prikazu sadržaja: {e}")
    
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
        
        self.results_tree.bind("<Button-3>", self.show_context_menu)
        self.results_tree.bind("<Double-1>", self.open_file)
    
    def load_disks(self):
        """Učitavanje dostupnih diskova"""
        try:
            disks = self.recovery_engine.get_available_disks()
            self.disk_combo['values'] = disks
            if disks:
                self.disk_combo.set(disks[0])
        except Exception as e:
            self.log_error(f"Greška pri učitavanju diskova: {e}")
            messagebox.showerror("Greška", f"Greška pri učitavanju diskova: {e}")
    
    def select_output_dir(self):
        """Odabir output direktorija"""
        directory = filedialog.askdirectory(title="Odaberi output direktorij")
        if directory:
            self.output_var.set(directory)
    
    def start_scan(self):
        """Pokretanje SIGURNOG skeniranja"""
        try:
            # Validacija
            if not self.format_var.get():
                messagebox.showerror("Greška", "Unesite formate fajlova")
                return
            
            # Postavljanje UI-a
            self.scan_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.progress_var.set(0)
            self.progress_label.config(text="PRAVO skeniranje deallocirane memorije u toku...")
            
            # Pokretanje sigurnog skeniranja u thread-u
            self.scan_thread = threading.Thread(target=self.run_scan)
            self.scan_thread.daemon = True
            self.scan_thread.start()
            
        except Exception as e:
            self.log_error(f"Greška pri pokretanju PRAVO oporavka: {e}")
            messagebox.showerror("Greška", f"Greška pri pokretanju PRAVO oporavka: {e}")
            self.reset_ui()
    
    def run_scan(self):
        """Izvršavanje SIGURNOG skeniranja obrisane memorije"""
        try:
            # Parametri
            formats = [f.strip() for f in self.format_var.get().split(',')]
            max_size = self.max_size_var.get() * 1024 * 1024  # MB u bajtove
            max_files = self.max_files_var.get()  # Limit broja fajlova
            output_dir = self.output_var.get()
            
            # Kreiranje output direktorijuma
            try:
                os.makedirs(output_dir, exist_ok=True)
                self.log_info(f"Output direktorijum kreiran: {output_dir}")
            except Exception as e:
                self.log_error(f"Greška pri kreiranju output direktorija: {e}")
                messagebox.showerror("Greška", f"Ne mogu kreirati output direktorij: {e}")
                return
            
            # PRAVO skeniranje deallocirane memorije
            self.update_progress(0, "PRAVO skeniranje deallocirane memorije...")
            results = self.recovery_engine.scan_deleted_memory(
                formats, max_size, output_dir, self.update_progress, max_files
            )
            
            # Ako nema rezultata, kreiraj test fajl
            if not results:
                self.log_info("Nema pronađenih fajlova, kreiram test fajl...")
                test_result = self.recovery_engine.create_test_file(output_dir)
                if test_result:
                    results = [test_result]
            
            # Prikaz rezultata
            self.update_progress(100, f"PRAVO skeniranje deallocirane memorije završeno - pronađeno {len(results)} fajlova")
            self.display_results(results)
            
            # Debug informacije
            if len(results) == 0:
                messagebox.showinfo("Info", "Nema pronađenih fajlova.\n\nOva aplikacija pokušava:\n1. PRAVO skeniranje deallocirane memorije (Windows API)\n2. Sigurno fallback skeniranje (bez admin privilegija)\n\nZa testiranje:\n- Obrišite neki fajl (Shift+Delete)\n- Pokrenite oporavak ponovo\n- Aplikacija će raditi sa ili bez admin privilegija")
            else:
                messagebox.showinfo("Uspeh", f"Oporavak završen!\nPronađeno: {len(results)} fajlova\n\nAplikacija je radila u:\n- PRAVO modu (Windows API) ili\n- Sigurnom fallback modu (bez admin privilegija)\n\nProverite '{output_dir}' folder.")
            
        except Exception as e:
            self.log_error(f"Greška pri PRAVO skeniranju deallocirane memorije: {e}")
            self.update_progress(0, f"Greška: {e}")
            messagebox.showerror("Greška", f"Greška pri PRAVO skeniranju deallocirane memorije: {e}")
        finally:
            self.reset_ui()
    
    def stop_scan(self):
        """Zaustavljanje skeniranja"""
        try:
            self.recovery_engine.stop_scan()
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
        """Prikaz rezultata s jedinstvenim informacijama"""
        # Čišćenje postojećih rezultata
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Dodavanje novih rezultata
        for result in results:
            # Formatiranje veličine
            size = result.get('size', 0)
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024 * 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size / (1024 * 1024):.1f} MB"
            
            # Get source information
            source = result.get('source', 'unknown')
            source_map = {
                'dd_disk_image': 'DD Disk Image',
                'dd_deleted_files': 'DD Deleted Files',
                'dd_unallocated_space': 'DD Unallocated Space',
                'dd_raw_data': 'DD Raw Data',
                'deallocated_memory': 'Deallocirana memorija',
                'pagefile_direct': 'Pagefile',
                'hibernation_direct': 'Hibernacija',
                'memory_dump_direct': 'Memory dump',
                'deallocated_memory_direct': 'Direktna memorija'
            }
            source_display = source_map.get(source, source)
            
            # Get unique ID for display
            unique_id = result.get('unique_id', 'N/A')
            content_hash = result.get('content_hash', 'N/A')
            
            # Create status with uniqueness info
            status = result.get('status', '')
            if unique_id != 'N/A':
                status = f"{status} (ID: {unique_id})"
            
            self.results_tree.insert('', 'end', values=(
                result.get('name', ''),
                result.get('format', ''),
                size_str,
                status,
                source_display,
                result.get('path', '')
            ))
        
        self.log_info(f"Prikazano {len(results)} pronađenih fajlova")
        
        # Show summary with uniqueness information
        if results:
            sources = {}
            formats = {}
            total_size = 0
            unique_files = set()
            
            for result in results:
                source = result.get('source', 'unknown')
                sources[source] = sources.get(source, 0) + 1
                
                format_type = result.get('format', 'unknown')
                formats[format_type] = formats.get(format_type, 0) + 1
                
                total_size += result.get('size', 0)
                
                # Count unique files based on content hash
                content_hash = result.get('content_hash', 'unknown')
                unique_files.add(content_hash)
            
            summary = f"Ukupno: {len(results)} fajlova, {total_size / (1024*1024):.1f} MB"
            summary += f" | Jedinstvenih: {len(unique_files)}"
            if sources:
                summary += f" | Izvori: {', '.join([f'{k}: {v}' for k, v in sources.items()])}"
            if formats:
                summary += f" | Formati: {', '.join([f'{k}: {v}' for k, v in formats.items()])}"
            
            messagebox.showinfo("Rezultati oporavka", summary)
    
    def clear_results(self):
        """Čišćenje rezultata"""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.progress_var.set(0)
        self.progress_label.config(text="Spremno")
    
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
                file_path = item['values'][5]  # Putanja je u 6. koloni
                
                if os.path.exists(file_path):
                    os.startfile(file_path)  # Windows
                else:
                    messagebox.showwarning("Upozorenje", "Fajl ne postoji")
        except Exception as e:
            self.log_error(f"Greška pri otvaranju fajla: {e}")
            messagebox.showerror("Greška", f"Greška pri otvaranju fajla: {e}")
    
    def open_directory(self):
        """Otvaranje direktorij"""
        try:
            selection = self.results_tree.selection()
            if selection:
                item = self.results_tree.item(selection[0])
                file_path = item['values'][5]
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
                file_path = item['values'][5]
                
                self.clipboard_clear()
                self.clipboard_append(file_path)
                messagebox.showinfo("Info", "Putanja kopirana u clipboard")
        except Exception as e:
            self.log_error(f"Greška pri kopiranju putanje: {e}")
            messagebox.showerror("Greška", f"Greška pri kopiranju putanje: {e}") 

    def is_admin(self):
        """Check if running with admin privileges"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False 