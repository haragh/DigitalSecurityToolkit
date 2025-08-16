#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YARA Scanner Module - Skeniranje zlonamjernog softvera
"""

import os
import zipfile
import tarfile
import threading
from datetime import datetime
from utils.logger import LoggerMixin

# Provera da li je yara dostupan
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

class YaraScanner(LoggerMixin):
    """Klasa za YARA skeniranje"""
    
    def __init__(self, config, logger):
        super().__init__("YaraScanner")
        self.config = config
        self.logger = logger
        self.stop_scan = False
        self.rules = {}
        self.compiled_rules = {}
        
        # Učitavanje default pravila
        try:
            self.load_default_rules()
        except Exception as e:
            self.log_error(f"Greška pri učitavanju default pravila: {e}")
            # Nastavi bez pravila - korisnik može učitati kasnije
    
    def load_default_rules(self):
        """Učitavanje default YARA pravila"""
        if not YARA_AVAILABLE:
            self.log_error("YARA modul nije dostupan. Instalirajte: pip install yara-python")
            return
            
        try:
            # Osnovna pravila za malware detekciju
            default_rules = {
                'suspicious_strings': '''
                    rule suspicious_strings {
                        strings:
                            $s1 = "cmd.exe" nocase
                            $s2 = "powershell" nocase
                            $s3 = "regsvr32" nocase
                            $s4 = "rundll32" nocase
                            $s5 = "schtasks" nocase
                            $s6 = "wmic" nocase
                            $s7 = "netcat" nocase
                            $s8 = "nc.exe" nocase
                            $s9 = "meterpreter" nocase
                            $s10 = "shellcode" nocase
                        
                        condition:
                            any of them
                    }
                ''',
                
                'packed_executable': '''
                    rule packed_executable {
                        strings:
                            $mz = "MZ"
                            $pe = "PE"
                            $upx = "UPX"
                            $aspack = "ASPack"
                            $upack = "UPack"
                        
                        condition:
                            $mz at 0 and $pe and ($upx or $aspack or $upack)
                    }
                ''',
                
                'network_activity': '''
                    rule network_activity {
                        strings:
                            $http = "http://" nocase
                            $https = "https://" nocase
                            $ftp = "ftp://" nocase
                            $ip = /\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/
                            $port = /:\\d{1,5}/
                        
                        condition:
                            ($http or $https or $ftp) and ($ip or $port)
                    }
                ''',
                
                'registry_modifications': '''
                    rule registry_modifications {
                        meta:
                            description = "Detects registry modification attempts"
                            author = "Digital Security Toolkit"
                            severity = "medium"
                        
                        strings:
                            $reg1 = "HKEY_LOCAL_MACHINE" nocase
                            $reg2 = "HKEY_CURRENT_USER" nocase
                            $reg3 = "HKEY_CLASSES_ROOT" nocase
                            $reg4 = "HKEY_USERS" nocase
                            $reg5 = "HKEY_CURRENT_CONFIG" nocase
                            $reg6 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase
                            $reg7 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce" nocase
                        
                        condition:
                            any of ($reg1, $reg2, $reg3, $reg4, $reg5) and any of ($reg6, $reg7)
                    }
                '''
            }
            
            # Kompajliranje pravila
            for rule_name, rule_content in default_rules.items():
                try:
                    compiled_rule = yara.compile(source=rule_content)
                    self.compiled_rules[rule_name] = compiled_rule
                    self.log_info(f"Učitano default pravilo: {rule_name}")
                except Exception as e:
                    self.log_error(f"Greška pri kompajliranju pravila {rule_name}: {e}")
            
        except Exception as e:
            self.log_error(f"Greška pri učitavanju default pravila: {e}")
    
    def load_rules_from_directory(self, rules_dir):
        """Učitavanje YARA pravila iz direktorijuma"""
        if not YARA_AVAILABLE:
            self.log_error("YARA modul nije dostupan. Instalirajte: pip install yara-python")
            return 0
            
        try:
            rules_count = 0
            
            if not os.path.exists(rules_dir):
                self.log_error(f"Direktorijum pravila ne postoji: {rules_dir}")
                return 0
            
            for filename in os.listdir(rules_dir):
                if filename.endswith(('.yar', '.yara', '.rule')):
                    rule_path = os.path.join(rules_dir, filename)
                    try:
                        # Učitavanje pravila
                        rules = yara.compile(rule_path)
                        rule_name = os.path.splitext(filename)[0]
                        self.compiled_rules[rule_name] = rules
                        rules_count += 1
                        self.log_info(f"Učitano pravilo: {rule_name}")
                    except Exception as e:
                        self.log_error(f"Greška pri učitavanju pravila {filename}: {e}")
                        # Nastavi sa sledećim pravilom
                        continue
            
            self.log_info(f"Ukupno učitano {rules_count} pravila")
            return rules_count
            
        except Exception as e:
            self.log_error(f"Greška pri učitavanju pravila iz direktorijuma: {e}")
            return 0
    
    def scan_target(self, target, rules_dir, recursive, scan_archives, verbose, max_size, progress_callback=None):
        """
        Skeniranje cilja sa YARA pravilima
        
        Args:
            target (str): Putanja do cilja (fajl ili direktorijum)
            rules_dir (str): Direktorijum sa YARA pravilima
            recursive (bool): Rekurzivno skeniranje
            scan_archives (bool): Skeniranje arhiva
            verbose (bool): Detaljni izvještaj
            max_size (int): Maksimalna veličina fajla
            progress_callback (function): Callback za progress
        
        Returns:
            list: Lista rezultata skeniranja
        """
        if not YARA_AVAILABLE:
            self.log_error("YARA modul nije dostupan. Instalirajte: pip install yara-python")
            return []
            
        try:
            self.stop_scan = False
            results = []
            
            # Učitavanje pravila ako nije već učitano
            if rules_dir and rules_dir not in self.rules:
                self.load_rules_from_directory(rules_dir)
            
            # Skeniranje
            if os.path.isfile(target):
                results = self.scan_file(target, verbose, max_size, progress_callback)
            elif os.path.isdir(target):
                results = self.scan_directory(target, recursive, scan_archives, verbose, max_size, progress_callback)
            else:
                self.log_error(f"Cilj ne postoji: {target}")
                return []
            
            self.log_info(f"Skeniranje završeno. Pronađeno {len(results)} rezultata")
            return results
            
        except Exception as e:
            self.log_error(f"Greška pri skeniranju: {e}")
            return []
    
    def scan_file(self, file_path, verbose, max_size, progress_callback=None):
        """Skeniranje pojedinačnog fajla"""
        try:
            results = []
            
            # Provjera veličine
            if os.path.getsize(file_path) > max_size:
                self.log_info(f"Fajl prevelik za skeniranje: {file_path}")
                return results
            
            # Provjera da li je arhiva
            if self.is_archive(file_path):
                if verbose:
                    self.log_info(f"Skeniranje arhive: {file_path}")
                archive_results = self.scan_archive(file_path, verbose, max_size)
                results.extend(archive_results)
            else:
                # Skeniranje običnog fajla
                file_results = self.scan_single_file(file_path, verbose)
                results.extend(file_results)
            
            return results
            
        except Exception as e:
            self.log_error(f"Greška pri skeniranju fajla {file_path}: {e}")
            return []
    
    def scan_directory(self, directory_path, recursive, scan_archives, verbose, max_size, progress_callback=None):
        """Skeniranje direktorijuma"""
        try:
            results = []
            total_files = 0
            processed_files = 0
            
            # Brojanje fajlova za progress
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    total_files += len(files)
            else:
                total_files = len([f for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f))])
            
            # Skeniranje
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    if self.stop_scan:
                        break
                    
                    for file in files:
                        if self.stop_scan:
                            break
                        
                        file_path = os.path.join(root, file)
                        file_results = self.scan_file(file_path, verbose, max_size)
                        results.extend(file_results)
                        
                        processed_files += 1
                        if progress_callback:
                            progress = (processed_files / total_files) * 100
                            progress_callback(progress, f"Skeniranje {file_path}...")
            else:
                for file in os.listdir(directory_path):
                    if self.stop_scan:
                        break
                    
                    file_path = os.path.join(directory_path, file)
                    if os.path.isfile(file_path):
                        file_results = self.scan_file(file_path, verbose, max_size)
                        results.extend(file_results)
                        
                        processed_files += 1
                        if progress_callback:
                            progress = (processed_files / total_files) * 100
                            progress_callback(progress, f"Skeniranje {file_path}...")
            
            return results
            
        except Exception as e:
            self.log_error(f"Greška pri skeniranju direktorijuma: {e}")
            return []
    
    def scan_single_file(self, file_path, verbose):
        """Skeniranje pojedinačnog fajla sa YARA pravilima"""
        try:
            results = []
            
            # Skeniranje sa svim pravilima
            for rule_name, compiled_rule in self.compiled_rules.items():
                try:
                    matches = compiled_rule.match(file_path)
                    
                    for match in matches:
                        result = {
                            'file': file_path,
                            'rule': rule_name,
                            'severity': self.get_severity(rule_name),
                            'details': f"Match: {match.rule}",
                            'status': 'detected'
                        }
                        results.append(result)
                        
                        if verbose:
                            self.log_info(f"Match pronađen: {rule_name} u {file_path}")
                
                except Exception as e:
                    self.log_error(f"Greška pri skeniranju sa pravilom {rule_name}: {e}")
                    continue
            
            return results
            
        except Exception as e:
            self.log_error(f"Greška pri skeniranju fajla {file_path}: {e}")
            return []
    
    def is_archive(self, file_path):
        """Provjera da li je fajl arhiva"""
        try:
            file_ext = os.path.splitext(file_path)[1].lower()
            return file_ext in ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']
        except:
            return False
    
    def scan_archive(self, archive_path, verbose, max_size):
        """Skeniranje arhive"""
        try:
            results = []
            file_ext = os.path.splitext(archive_path)[1].lower()
            
            if file_ext == '.zip':
                results = self.scan_zip_archive(archive_path, verbose, max_size)
            elif file_ext in ['.tar', '.gz', '.bz2']:
                results = self.scan_tar_archive(archive_path, verbose, max_size)
            # Dodati podršku za ostale formate arhiva
            
            return results
            
        except Exception as e:
            self.log_error(f"Greška pri skeniranju arhive {archive_path}: {e}")
            return []
    
    def scan_zip_archive(self, archive_path, verbose, max_size):
        """Skeniranje ZIP arhive"""
        try:
            results = []
            
            with zipfile.ZipFile(archive_path, 'r') as zip_file:
                for file_info in zip_file.filelist:
                    if self.stop_scan:
                        break
                    
                    # Provjera veličine
                    if file_info.file_size > max_size:
                        continue
                    
                    # Čitanje fajla iz arhive
                    try:
                        with zip_file.open(file_info.filename) as file_in_archive:
                            file_data = file_in_archive.read()
                            
                            # Skeniranje podataka
                            for rule_name, compiled_rule in self.compiled_rules.items():
                                try:
                                    matches = compiled_rule.match(data=file_data)
                                    
                                    for match in matches:
                                        result = {
                                            'file': f"{archive_path}/{file_info.filename}",
                                            'rule': rule_name,
                                            'severity': self.get_severity(rule_name),
                                            'details': f"Match in archive: {match.rule}",
                                            'status': 'detected'
                                        }
                                        results.append(result)
                                        
                                        if verbose:
                                            self.log_info(f"Match u arhivi: {rule_name} u {file_info.filename}")
                                
                                except Exception as e:
                                    self.log_error(f"Greška pri skeniranju arhiviranog fajla: {e}")
                                    continue
                    
                    except Exception as e:
                        self.log_error(f"Greška pri čitanju fajla iz arhive: {e}")
                        continue
            
            return results
            
        except Exception as e:
            self.log_error(f"Greška pri skeniranju ZIP arhive: {e}")
            return []
    
    def scan_tar_archive(self, archive_path, verbose, max_size):
        """Skeniranje TAR arhive"""
        try:
            results = []
            
            with tarfile.open(archive_path, 'r:*') as tar_file:
                for member in tar_file.getmembers():
                    if self.stop_scan:
                        break
                    
                    if not member.isfile():
                        continue
                    
                    # Provjera veličine
                    if member.size > max_size:
                        continue
                    
                    # Čitanje fajla iz arhive
                    try:
                        file_obj = tar_file.extractfile(member)
                        if file_obj:
                            file_data = file_obj.read()
                            
                            # Skeniranje podataka
                            for rule_name, compiled_rule in self.compiled_rules.items():
                                try:
                                    matches = compiled_rule.match(data=file_data)
                                    
                                    for match in matches:
                                        result = {
                                            'file': f"{archive_path}/{member.name}",
                                            'rule': rule_name,
                                            'severity': self.get_severity(rule_name),
                                            'details': f"Match in archive: {match.rule}",
                                            'status': 'detected'
                                        }
                                        results.append(result)
                                        
                                        if verbose:
                                            self.log_info(f"Match u arhivi: {rule_name} u {member.name}")
                                
                                except Exception as e:
                                    self.log_error(f"Greška pri skeniranju arhiviranog fajla: {e}")
                                    continue
                    
                    except Exception as e:
                        self.log_error(f"Greška pri čitanju fajla iz arhive: {e}")
                        continue
            
            return results
            
        except Exception as e:
            self.log_error(f"Greška pri skeniranju TAR arhive: {e}")
            return []
    
    def get_severity(self, rule_name):
        """Određivanje intenziteta pravila"""
        high_severity = ['suspicious_strings', 'packed_executable', 'network_activity']
        medium_severity = ['registry_modifications']
        
        if rule_name in high_severity:
            return 'High'
        elif rule_name in medium_severity:
            return 'Medium'
        else:
            return 'Low'
    
    def save_results(self, results, output_file):
        """Čuvanje rezultata skeniranja"""
        try:
            import json
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
            
            self.log_info(f"Rezultati sačuvani u {output_file}")
            
        except Exception as e:
            self.log_error(f"Greška pri čuvanju rezultata: {e}")
    
    def stop_scanning(self):
        """Zaustavljanje skeniranja"""
        self.stop_scan = True
        self.log_info("YARA skeniranje zaustavljeno") 