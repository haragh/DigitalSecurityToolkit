#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Timeline Analyzer Module - Vremenska linija aktivnosti
"""

import os
import stat
import threading
from datetime import datetime, timedelta
from utils.logger import LoggerMixin

class TimelineAnalyzer(LoggerMixin):
    """Klasa za analizu vremenske linije aktivnosti"""
    
    def __init__(self, config, logger):
        super().__init__("TimelineAnalyzer")
        self.config = config
        self.logger = logger
        self.stop_analysis = False
        
        # MAC timestamp-ovi
        self.mac_timestamps = {
            'modified': 'mtime',
            'accessed': 'atime', 
            'created': 'ctime'
        }
    
    def analyze_timeline(self, directory_path, start_date, end_date, include_deleted, 
                        include_system, recursive, filters, progress_callback=None):
        """
        Analiza vremenske linije aktivnosti
        """
        try:
            self.stop_analysis = False
            activities = []
            
            # Analiza direktorijuma
            if recursive:
                activities = self.analyze_directory_recursive(
                    directory_path, start_date, end_date, include_deleted, 
                    include_system, filters, progress_callback
                )
            else:
                activities = self.analyze_directory(
                    directory_path, start_date, end_date, include_deleted,
                    include_system, filters, progress_callback
                )
            
            # Sortiranje po najnovijem MAC vremenu
            def get_latest_mac(activity):
                times = [activity.get('modified'), activity.get('accessed'), activity.get('created')]
                times = [t for t in times if t]
                if not times:
                    return ''
                return max(times)
            activities.sort(key=get_latest_mac, reverse=True)
            
            self.log_info(f"Analiza završena. Pronađeno {len(activities)} aktivnosti")
            return activities
            
        except Exception as e:
            self.log_error(f"Greška pri analizi vremenske linije: {e}")
            return []
    
    def analyze_directory(self, directory_path, start_date, end_date, include_deleted, 
                         include_system, filters, progress_callback=None):
        """Analiza direktorijuma (bez rekurzije)"""
        try:
            activities = []
            
            if not os.path.exists(directory_path):
                self.log_error(f"Direktorijum ne postoji: {directory_path}")
                return activities
            
            # Lista fajlova u direktorijumu
            try:
                files = os.listdir(directory_path)
            except PermissionError:
                self.log_warning(f"Nema dozvole za pristup: {directory_path}")
                return activities
            
            total_files = len(files)
            processed_files = 0
            
            for filename in files:
                if self.stop_analysis:
                    break
                
                file_path = os.path.join(directory_path, filename)
                
                try:
                    # Provjera sistemskih fajlova
                    if not include_system and self.is_system_file(file_path):
                        continue
                    
                    # Analiza fajla
                    file_activities = self.analyze_file_timestamps(
                        file_path, start_date, end_date, filters
                    )
                    activities.extend(file_activities)
                    
                except Exception as e:
                    self.log_error(f"Greška pri analizi fajla {file_path}: {e}")
                    continue
                
                processed_files += 1
                if progress_callback:
                    progress = (processed_files / total_files) * 100
                    progress_callback(progress, f"Analiza {file_path}...")
            
            return activities
            
        except Exception as e:
            self.log_error(f"Greška pri analizi direktorijuma: {e}")
            return []
    
    def analyze_directory_recursive(self, directory_path, start_date, end_date, include_deleted,
                                   include_system, filters, progress_callback=None):
        """Rekurzivna analiza direktorijuma"""
        try:
            activities = []
            total_files = 0
            processed_files = 0
            
            # Brojanje fajlova za progress
            for root, dirs, files in os.walk(directory_path):
                total_files += len(files)
            
            # Analiza
            for root, dirs, files in os.walk(directory_path):
                if self.stop_analysis:
                    break
                
                for filename in files:
                    if self.stop_analysis:
                        break
                    
                    file_path = os.path.join(root, filename)
                    
                    try:
                        # Provjera sistemskih fajlova
                        if not include_system and self.is_system_file(file_path):
                            continue
                        
                        # Analiza fajla
                        file_activities = self.analyze_file_timestamps(
                            file_path, start_date, end_date, filters
                        )
                        activities.extend(file_activities)
                        
                    except Exception as e:
                        self.log_error(f"Greška pri analizi fajla {file_path}: {e}")
                        continue
                    
                    processed_files += 1
                    if progress_callback:
                        progress = (processed_files / total_files) * 100
                        progress_callback(progress, f"Analiza {file_path}...")
            
            return activities
            
        except Exception as e:
            self.log_error(f"Greška pri rekurzivnoj analizi: {e}")
            return []
    
    def analyze_file_timestamps(self, file_path, start_date, end_date, filters):
        """Analiza timestamp-ova fajla ili direktorijuma - sada vraća sve MAC vrijednosti i veličinu"""
        try:
            activities = []
            
            if not os.path.exists(file_path):
                return activities
            
            # Dobijanje stat informacija
            try:
                stat_info = os.stat(file_path)
            except (OSError, PermissionError):
                return activities
            
            # Priprema MAC vremena
            def get_time(attr):
                try:
                    if hasattr(stat_info, attr):
                        return datetime.fromtimestamp(getattr(stat_info, attr)).isoformat()
                    # Fallback
                    if attr == 'st_mtime':
                        return datetime.fromtimestamp(stat_info.st_ctime).isoformat() if hasattr(stat_info, 'st_ctime') else ''
                    if attr == 'st_atime':
                        return datetime.fromtimestamp(stat_info.st_ctime).isoformat() if hasattr(stat_info, 'st_ctime') else ''
                    if attr == 'st_ctime':
                        return datetime.fromtimestamp(stat_info.st_mtime).isoformat() if hasattr(stat_info, 'st_mtime') else ''
                except Exception:
                    return ''
                return ''
            
            modified = get_time('st_mtime')
            accessed = get_time('st_atime')
            created = get_time('st_ctime')
            
            # Veličina
            if os.path.isdir(file_path):
                # Za direktorijume, rekurzivno izračunaj veličinu
                total_size = 0
                for dirpath, dirnames, filenames in os.walk(file_path):
                    for f in filenames:
                        fp = os.path.join(dirpath, f)
                        try:
                            if os.path.isfile(fp):
                                total_size += os.path.getsize(fp)
                        except Exception:
                            continue
                size = total_size
            else:
                size = stat_info.st_size if hasattr(stat_info, 'st_size') else 0
            
            # Prikazujemo samo ako je bar jedan od MAC vremena u opsegu
            in_range = False
            for t in [modified, accessed, created]:
                try:
                    if t:
                        dt = datetime.fromisoformat(t)
                        if start_date <= dt <= end_date:
                            in_range = True
                            break
                except Exception:
                    continue
            if not in_range:
                return activities
                
            activity = {
                'filename': os.path.basename(file_path),
                'path': file_path,
                'size': size,
                'modified': modified,
                'accessed': accessed,
                'created': created,
                'permissions': oct(stat_info.st_mode)[-3:] if hasattr(stat_info, 'st_mode') else '000',
                'owner': stat_info.st_uid if hasattr(stat_info, 'st_uid') else 'N/A',
                'group': stat_info.st_gid if hasattr(stat_info, 'st_gid') else 'N/A',
                'type': 'directory' if os.path.isdir(file_path) else 'file',
            }
            activities.append(activity)
            return activities
        except Exception as e:
            self.log_error(f"Greška pri analizi timestamp-ova {file_path}: {e}")
            return []
    
    def is_system_file(self, file_path):
        """Provjera da li je sistemski fajl"""
        try:
            # Windows sistemski fajlovi
            if os.name == 'nt':
                system_dirs = ['windows', 'system32', 'syswow64', '$recycle.bin', 'system volume information']
                file_path_lower = file_path.lower()
                return any(system_dir in file_path_lower for system_dir in system_dirs)
            
            # Unix/Linux sistemski fajlovi
            else:
                system_dirs = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/lib', '/usr/lib', '/proc', '/sys']
                return any(file_path.startswith(system_dir) for system_dir in system_dirs)
            
        except Exception as e:
            self.log_error(f"Greška pri provjeri sistemskog fajla: {e}")
            return False
    
    def get_file_metadata(self, file_path):
        """Dobijanje metapodataka fajla"""
        try:
            metadata = {}
            
            if not os.path.exists(file_path):
                return metadata
            
            stat_info = os.stat(file_path)
            
            # Sigurno pristupanje stat atributima
            metadata['size'] = stat_info.st_size if hasattr(stat_info, 'st_size') else 0
            metadata['permissions'] = oct(stat_info.st_mode)[-3:] if hasattr(stat_info, 'st_mode') else '000'
            
            # Timestamp-ovi sa fallback-om
            try:
                if hasattr(stat_info, 'st_mtime'):
                    metadata['modified'] = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                elif hasattr(stat_info, 'st_ctime'):
                    metadata['modified'] = datetime.fromtimestamp(stat_info.st_ctime).isoformat()
                else:
                    metadata['modified'] = datetime.now().isoformat()
            except (OSError, ValueError):
                metadata['modified'] = datetime.now().isoformat()
            
            try:
                if hasattr(stat_info, 'st_atime'):
                    metadata['accessed'] = datetime.fromtimestamp(stat_info.st_atime).isoformat()
                elif hasattr(stat_info, 'st_ctime'):
                    metadata['accessed'] = datetime.fromtimestamp(stat_info.st_ctime).isoformat()
                else:
                    metadata['accessed'] = datetime.now().isoformat()
            except (OSError, ValueError):
                metadata['accessed'] = datetime.now().isoformat()
            
            try:
                if hasattr(stat_info, 'st_ctime'):
                    metadata['created'] = datetime.fromtimestamp(stat_info.st_ctime).isoformat()
                elif hasattr(stat_info, 'st_mtime'):
                    metadata['created'] = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                else:
                    metadata['created'] = datetime.now().isoformat()
            except (OSError, ValueError):
                metadata['created'] = datetime.now().isoformat()
            
            # Dodatni metapodaci
            if hasattr(stat_info, 'st_uid'):
                metadata['owner'] = stat_info.st_uid
            if hasattr(stat_info, 'st_gid'):
                metadata['group'] = stat_info.st_gid
            
            return metadata
            
        except Exception as e:
            self.log_error(f"Greška pri dobijanju metapodataka: {e}")
            return {}
    
    def analyze_recent_activities(self, directory_path, hours=24):
        """Analiza nedavnih aktivnosti"""
        try:
            end_date = datetime.now()
            start_date = end_date - timedelta(hours=hours)
            
            activities = self.analyze_timeline(
                directory_path, start_date, end_date, 
                include_deleted=True, include_system=False, 
                recursive=True, filters=['modified', 'accessed', 'created']
            )
            
            return activities
            
        except Exception as e:
            self.log_error(f"Greška pri analizi nedavnih aktivnosti: {e}")
            return []
    
    def find_anomalies(self, activities):
        """Pronalaženje anomalija u aktivnostima"""
        try:
            anomalies = []
            
            # Grupisanje aktivnosti po vremenu
            time_groups = {}
            for activity in activities:
                timestamp = datetime.fromisoformat(activity['timestamp'])
                hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
                
                if hour_key not in time_groups:
                    time_groups[hour_key] = []
                time_groups[hour_key].append(activity)
            
            # Pronalaženje anomalija
            for hour, hour_activities in time_groups.items():
                # Ako je previše aktivnosti u jednom satu
                if len(hour_activities) > 100:
                    anomaly = {
                        'type': 'high_activity',
                        'timestamp': hour.isoformat(),
                        'count': len(hour_activities),
                        'description': f"Visoka aktivnost: {len(hour_activities)} događaja u {hour.strftime('%H:%M')}"
                    }
                    anomalies.append(anomaly)
                
                # Provjera sumnjivih aktivnosti
                for activity in hour_activities:
                    if self.is_suspicious_activity(activity):
                        anomaly = {
                            'type': 'suspicious_activity',
                            'timestamp': activity['timestamp'],
                            'file': activity['filename'],
                            'action': activity['action'],
                            'description': f"Sumnjiva aktivnost: {activity['action']} na {activity['filename']}"
                        }
                        anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            self.log_error(f"Greška pri pronalaženju anomalija: {e}")
            return []
    
    def is_suspicious_activity(self, activity):
        """Provjera da li je aktivnost sumnjiva"""
        try:
            filename = activity['filename'].lower()
            action = activity['action']
            
            # Sumnjivi fajlovi
            suspicious_files = [
                'cmd.exe', 'powershell.exe', 'regsvr32.exe', 'rundll32.exe',
                'schtasks.exe', 'wmic.exe', 'netcat.exe', 'nc.exe',
                '.bat', '.cmd', '.ps1', '.vbs', '.js'
            ]
            
            # Sumnjive aktivnosti
            suspicious_actions = ['modified', 'created']
            
            # Provjera
            if any(suspicious_file in filename for suspicious_file in suspicious_files):
                if action in suspicious_actions:
                    return True
            
            return False
            
        except Exception as e:
            self.log_error(f"Greška pri provjeri sumnjive aktivnosti: {e}")
            return False
    
    def generate_summary(self, activities):
        """Generisanje sažetka aktivnosti"""
        try:
            summary = {
                'total_activities': len(activities),
                'time_period': {},
                'file_types': {},
                'actions': {},
                'most_active_hours': {},
                'largest_files': []
            }
            
            if not activities:
                return summary
            
            # Vremenski period
            timestamps = [datetime.fromisoformat(activity['timestamp']) for activity in activities]
            summary['time_period'] = {
                'start': min(timestamps).isoformat(),
                'end': max(timestamps).isoformat()
            }
            
            # Tipovi fajlova
            for activity in activities:
                file_ext = os.path.splitext(activity['filename'])[1].lower()
                if file_ext:
                    summary['file_types'][file_ext] = summary['file_types'].get(file_ext, 0) + 1
                else:
                    summary['file_types']['no_extension'] = summary['file_types'].get('no_extension', 0) + 1
            
            # Akcije
            for activity in activities:
                action = activity['action']
                summary['actions'][action] = summary['actions'].get(action, 0) + 1
            
            # Najaktivniji sati
            hour_counts = {}
            for activity in activities:
                timestamp = datetime.fromisoformat(activity['timestamp'])
                hour = timestamp.hour
                hour_counts[hour] = hour_counts.get(hour, 0) + 1
            
            # Top 5 najaktivnijih sati
            sorted_hours = sorted(hour_counts.items(), key=lambda x: x[1], reverse=True)
            summary['most_active_hours'] = dict(sorted_hours[:5])
            
            # Najveći fajlovi
            file_sizes = {}
            for activity in activities:
                filename = activity['filename']
                size = activity.get('size', 0)
                if filename not in file_sizes or size > file_sizes[filename]:
                    file_sizes[filename] = size
            
            # Top 10 najvećih fajlova
            sorted_files = sorted(file_sizes.items(), key=lambda x: x[1], reverse=True)
            summary['largest_files'] = [{'filename': filename, 'size': size} for filename, size in sorted_files[:10]]
            
            return summary
            
        except Exception as e:
            self.log_error(f"Greška pri generisanju sažetka: {e}")
            return {}
    
    def export_timeline(self, activities, output_format='json'):
        """Export vremenske linije"""
        try:
            if output_format == 'json':
                import json
                return json.dumps(activities, indent=4, ensure_ascii=False)
            
            elif output_format == 'csv':
                import csv
                import io
                
                output = io.StringIO()
                writer = csv.writer(output)
                
                # Header
                writer.writerow(['Timestamp', 'Filename', 'Path', 'Action', 'Size', 'Permissions'])
                
                # Podaci
                for activity in activities:
                    writer.writerow([
                        activity['timestamp'],
                        activity['filename'],
                        activity['path'],
                        activity['action'],
                        activity['size'],
                        activity['permissions']
                    ])
                
                return output.getvalue()
            
            else:
                raise ValueError(f"Nepodržan format: {output_format}")
            
        except Exception as e:
            self.log_error(f"Greška pri exportu vremenske linije: {e}")
            return None
    
    def stop_analysis(self):
        """Zaustavljanje analize"""
        self.stop_analysis = True
        self.log_info("Analiza vremenske linije zaustavljena") 