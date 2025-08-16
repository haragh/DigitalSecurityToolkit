#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Konfiguracija modul za Digital Security Toolkit
"""

import json
import os
from datetime import datetime
from utils.logger import LoggerMixin

class Config(LoggerMixin):
    """Klasa za upravljanje konfiguracijom aplikacije"""
    
    def __init__(self, config_file="data/config.json"):
        super().__init__("Config")
        self.config_file = config_file
        self.config = self.load_default_config()
        self.load()
    
    def load_default_config(self):
        """Učitavanje default konfiguracije"""
        return {
            "general": {
                "language": "bs",
                "theme": "default",
                "auto_save": True,
                "max_log_size": 10,  # MB
                "backup_count": 5
            },
            "file_recovery": {
                "scan_sectors": True,
                "max_file_size": 100,  # MB
                "supported_formats": [
                    "jpg", "jpeg", "png", "gif", "bmp",
                    "pdf", "doc", "docx", "txt", "rtf",
                    "zip", "rar", "7z", "mp3", "mp4", "avi"
                ],
                "output_directory": "recovered_files"
            },
            "yara_scanning": {
                "rules_directory": "rules",
                "scan_archives": True,
                "max_archive_size": 50,  # MB
                "timeout": 30,  # sekunde
                "recursive_scan": True
            },
            "integrity_check": {
                "hash_algorithms": ["sha256", "md5", "sha1"],
                "save_hashes": True,
                "hash_file": "data/file_hashes.json"
            },
            "timeline": {
                "max_entries": 10000,
                "include_deleted": True,
                "date_format": "%Y-%m-%d %H:%M:%S"
            },
            "monitoring": {
                "enabled": False,
                "check_interval": 5,  # sekunde
                "log_events": True,
                "alert_on_suspicious": True
            },
            "reporting": {
                "default_format": "pdf",
                "include_screenshots": True,
                "output_directory": "reports",
                "template_directory": "templates"
            },
            "security": {
                "require_admin": False,
                "scan_system_files": False,
                "quarantine_suspicious": False,
                "quarantine_directory": "quarantine"
            }
        }
    
    def load(self):
        """Učitavanje konfiguracije iz fajla"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    # Merge sa default konfiguracijom
                    self.merge_config(self.config, loaded_config)
                self.log_info(f"Konfiguracija učitana iz {self.config_file}")
            else:
                self.save()  # Kreiranje default konfiguracije
                self.log_info("Kreirana nova konfiguracija")
        except Exception as e:
            self.log_error(f"Greška pri učitavanju konfiguracije: {e}")
    
    def save(self):
        """Čuvanje konfiguracije u fajl"""
        try:
            # Kreiranje direktorijuma ako ne postoji
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            
            self.log_info(f"Konfiguracija sačuvana u {self.config_file}")
        except Exception as e:
            self.log_error(f"Greška pri čuvanju konfiguracije: {e}")
    
    def merge_config(self, default, loaded):
        """Spajanje default i učitane konfiguracije"""
        for key, value in loaded.items():
            if key in default:
                if isinstance(value, dict) and isinstance(default[key], dict):
                    self.merge_config(default[key], value)
                else:
                    default[key] = value
            else:
                default[key] = value
    
    def get(self, key_path, default=None):
        """
        Dobijanje vrijednosti iz konfiguracije
        
        Args:
            key_path (str): Putanja do vrijednosti (npr. "general.language")
            default: Default vrijednost ako ključ ne postoji
        
        Returns:
            Vrijednost iz konfiguracije
        """
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path, value):
        """
        Postavljanje vrijednosti u konfiguraciju
        
        Args:
            key_path (str): Putanja do vrijednosti
            value: Vrijednost za postavljanje
        """
        keys = key_path.split('.')
        config = self.config
        
        # Kreiranje putanje ako ne postoji
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value
        self.log_info(f"Konfiguracija ažurirana: {key_path} = {value}")
    
    def get_all(self):
        """Dobijanje cijele konfiguracije"""
        return self.config.copy()
    
    def reset_to_default(self):
        """Reset konfiguracije na default vrijednosti"""
        self.config = self.load_default_config()
        self.save()
        self.log_info("Konfiguracija resetovana na default vrijednosti")
    
    def export_config(self, file_path):
        """Export konfiguracije u fajl"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            self.log_info(f"Konfiguracija exportovana u {file_path}")
        except Exception as e:
            self.log_error(f"Greška pri exportu konfiguracije: {e}")
    
    def import_config(self, file_path):
        """Import konfiguracije iz fajla"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)
            
            self.merge_config(self.config, imported_config)
            self.save()
            self.log_info(f"Konfiguracija importovana iz {file_path}")
        except Exception as e:
            self.log_error(f"Greška pri importu konfiguracije: {e}") 