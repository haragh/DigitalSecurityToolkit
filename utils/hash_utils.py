#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hash utilities modul za Digital Security Toolkit
"""

import hashlib
import os
import json
from datetime import datetime
from utils.logger import LoggerMixin

class HashUtils(LoggerMixin):
    """Klasa za rad sa hash funkcijama"""
    
    def __init__(self):
        super().__init__("HashUtils")
        self.hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
    
    def calculate_file_hash(self, file_path, algorithm='sha256', chunk_size=8192):
        """
        Računanje hash-a fajla
        
        Args:
            file_path (str): Putanja do fajla
            algorithm (str): Hash algoritam (md5, sha1, sha256, sha512)
            chunk_size (int): Veličina chunk-a za čitanje
        
        Returns:
            str: Hash vrijednost ili None ako greška
        """
        try:
            if not os.path.exists(file_path):
                self.log_error(f"Fajl ne postoji: {file_path}")
                return None
            
            if algorithm not in self.hash_algorithms:
                self.log_error(f"Nepodržan hash algoritam: {algorithm}")
                return None
            
            hash_obj = self.hash_algorithms[algorithm]()
            
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    hash_obj.update(chunk)
            
            hash_value = hash_obj.hexdigest()
            self.log_info(f"Hash {algorithm} izračunat za {file_path}: {hash_value}")
            return hash_value
            
        except Exception as e:
            self.log_error(f"Greška pri računanju hash-a za {file_path}: {e}")
            return None
    
    def calculate_multiple_hashes(self, file_path, algorithms=None):
        """
        Računanje više hash algoritama za jedan fajl
        
        Args:
            file_path (str): Putanja do fajla
            algorithms (list): Lista hash algoritama
        
        Returns:
            dict: Rječnik sa hash vrijednostima
        """
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256']
        
        results = {}
        
        for algorithm in algorithms:
            hash_value = self.calculate_file_hash(file_path, algorithm)
            if hash_value:
                results[algorithm] = hash_value
        
        return results
    
    def verify_file_integrity(self, file_path, expected_hashes):
        """
        Provjera integriteta fajla
        
        Args:
            file_path (str): Putanja do fajla
            expected_hashes (dict): Očekivani hash-ovi
        
        Returns:
            dict: Rezultati provjere
        """
        results = {
            'file_path': file_path,
            'timestamp': datetime.now().isoformat(),
            'verification_results': {},
            'overall_status': 'unknown'
        }
        
        try:
            current_hashes = self.calculate_multiple_hashes(file_path, list(expected_hashes.keys()))
            
            all_match = True
            for algorithm, expected_hash in expected_hashes.items():
                if algorithm in current_hashes:
                    current_hash = current_hashes[algorithm]
                    match = current_hash.lower() == expected_hash.lower()
                    results['verification_results'][algorithm] = {
                        'expected': expected_hash,
                        'current': current_hash,
                        'match': match
                    }
                    if not match:
                        all_match = False
                else:
                    results['verification_results'][algorithm] = {
                        'expected': expected_hash,
                        'current': None,
                        'match': False
                    }
                    all_match = False
            
            results['overall_status'] = 'valid' if all_match else 'invalid'
            
            if all_match:
                self.log_info(f"Integritet fajla potvrđen: {file_path}")
            else:
                self.log_warning(f"Integritet fajla narušen: {file_path}")
            
        except Exception as e:
            self.log_error(f"Greška pri provjeri integriteta: {e}")
            results['overall_status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def scan_directory_hashes(self, directory_path, algorithms=None, file_extensions=None):
        """
        Skeniranje direktorijuma i računanje hash-ova
        
        Args:
            directory_path (str): Putanja do direktorijuma
            algorithms (list): Lista hash algoritama
            file_extensions (list): Lista ekstenzija za filtriranje
        
        Returns:
            dict: Rezultati skeniranja
        """
        if algorithms is None:
            algorithms = ['sha256']
        
        results = {
            'directory': directory_path,
            'timestamp': datetime.now().isoformat(),
            'files': {},
            'summary': {
                'total_files': 0,
                'processed_files': 0,
                'error_files': 0
            }
        }
        
        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Filtriranje po ekstenziji
                    if file_extensions:
                        file_ext = os.path.splitext(file)[1].lower()
                        if file_ext not in file_extensions:
                            continue
                    
                    results['summary']['total_files'] += 1
                    
                    try:
                        file_hashes = self.calculate_multiple_hashes(file_path, algorithms)
                        if file_hashes:
                            results['files'][file_path] = {
                                'hashes': file_hashes,
                                'size': os.path.getsize(file_path),
                                'modified': datetime.fromtimestamp(
                                    os.path.getmtime(file_path)
                                ).isoformat()
                            }
                            results['summary']['processed_files'] += 1
                        else:
                            results['summary']['error_files'] += 1
                    except Exception as e:
                        self.log_error(f"Greška pri obradi fajla {file_path}: {e}")
                        results['summary']['error_files'] += 1
            
            self.log_info(f"Skeniranje završeno: {results['summary']['processed_files']} fajlova obrađeno")
            
        except Exception as e:
            self.log_error(f"Greška pri skeniranju direktorijuma: {e}")
        
        return results
    
    def save_hash_database(self, hash_data, output_file):
        """
        Čuvanje hash baze podataka
        
        Args:
            hash_data (dict): Hash podaci
            output_file (str): Putanja do output fajla
        """
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(hash_data, f, indent=4, ensure_ascii=False)
            
            self.log_info(f"Hash baza podataka sačuvana: {output_file}")
            
        except Exception as e:
            self.log_error(f"Greška pri čuvanju hash baze: {e}")
    
    def load_hash_database(self, input_file):
        """
        Učitavanje hash baze podataka
        
        Args:
            input_file (str): Putanja do input fajla
        
        Returns:
            dict: Učitana hash baza podataka
        """
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                hash_data = json.load(f)
            
            self.log_info(f"Hash baza podataka učitana: {input_file}")
            return hash_data
            
        except Exception as e:
            self.log_error(f"Greška pri učitavanju hash baze: {e}")
            return {}
    
    def compare_hash_databases(self, db1, db2):
        """
        Poređenje dvije hash baze podataka
        
        Args:
            db1 (dict): Prva hash baza
            db2 (dict): Druga hash baza
        
        Returns:
            dict: Rezultati poređenja
        """
        results = {
            'added_files': [],
            'removed_files': [],
            'modified_files': [],
            'unchanged_files': []
        }
        
        files1 = set(db1.get('files', {}).keys())
        files2 = set(db2.get('files', {}).keys())
        
        # Dodani fajlovi
        results['added_files'] = list(files2 - files1)
        
        # Uklonjeni fajlovi
        results['removed_files'] = list(files1 - files2)
        
        # Zajednički fajlovi
        common_files = files1 & files2
        
        for file_path in common_files:
            hashes1 = db1['files'][file_path].get('hashes', {})
            hashes2 = db2['files'][file_path].get('hashes', {})
            
            if hashes1 == hashes2:
                results['unchanged_files'].append(file_path)
            else:
                results['modified_files'].append(file_path)
        
        return results 