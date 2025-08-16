#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
System Monitor Module - Nadzor sistema u stvarnom vremenu
"""

import os
import psutil
import threading
import time
from datetime import datetime
from utils.logger import LoggerMixin

class SystemMonitor(LoggerMixin):
    """Klasa za nadzor sistema"""
    
    def __init__(self, config, logger):
        super().__init__("SystemMonitor")
        self.config = config
        self.logger = logger
        
        # Stanje sistema
        self.previous_processes = set()
        self.previous_connections = set()
        self.previous_files = set()
        
        # Sumnjivi procesi
        self.suspicious_processes = [
            'cmd.exe', 'powershell.exe', 'regsvr32.exe', 'rundll32.exe',
            'schtasks.exe', 'wmic.exe', 'netcat.exe', 'nc.exe',
            'meterpreter', 'beacon', 'payload'
        ]
        
        # Sumnjivi portovi
        self.suspicious_ports = [
            22, 23, 80, 443, 8080, 8443, 3389, 5900, 5901
        ]
        
        # Sumnjivi fajlovi
        self.suspicious_extensions = [
            '.bat', '.cmd', '.ps1', '.vbs', '.js', '.exe', '.dll'
        ]
    
    def check_new_processes(self):
        """Provjera novih procesa"""
        try:
            current_processes = set()
            new_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    proc_info = proc.info
                    current_processes.add(proc_info['pid'])
                    
                    # Provjera da li je novi proces
                    if proc_info['pid'] not in self.previous_processes:
                        new_process = {
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                            'create_time': datetime.fromtimestamp(proc_info['create_time']).isoformat()
                        }
                        new_processes.append(new_process)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Ažuriranje prethodnog stanja
            self.previous_processes = current_processes
            
            return new_processes
            
        except Exception as e:
            self.log_error(f"Greška pri provjeri novih procesa: {e}")
            return []
    
    def check_suspicious_processes(self):
        """Provjera sumnjivih procesa"""
        try:
            suspicious = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_info = proc.info
                    process_name = proc_info['name'].lower()
                    cmdline = ' '.join(proc_info['cmdline']).lower() if proc_info['cmdline'] else ''
                    
                    # Provjera sumnjivih imena
                    for suspicious_name in self.suspicious_processes:
                        if suspicious_name in process_name or suspicious_name in cmdline:
                            suspicious.append({
                                'pid': proc_info['pid'],
                                'name': proc_info['name'],
                                'reason': f"Sumnjivo ime: {suspicious_name}",
                                'cmdline': cmdline
                            })
                            break
                    
                    # Provjera mrežnih konekcija
                    try:
                        connections = proc.connections()
                        for conn in connections:
                            if conn.raddr and conn.raddr.port in self.suspicious_ports:
                                suspicious.append({
                                    'pid': proc_info['pid'],
                                    'name': proc_info['name'],
                                    'reason': f"Sumnjiv port: {conn.raddr.port}",
                                    'cmdline': cmdline
                                })
                                break
                    except (psutil.AccessDenied, psutil.ZombieProcess, AttributeError, OSError):
                        pass
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            return suspicious
            
        except Exception as e:
            self.log_error(f"Greška pri provjeri sumnjivih procesa: {e}")
            return []
    
    def check_file_activities(self):
        """Provjera fajl aktivnosti"""
        try:
            activities = []
            
            # Ovo je pojednostavljena implementacija
            # U pravoj aplikaciji bi se koristio filesystem watcher
            
            # Provjera nedavno kreiranih fajlova
            temp_dirs = ['/tmp', '/temp', os.environ.get('TEMP', '')]
            
            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    try:
                        for filename in os.listdir(temp_dir):
                            file_path = os.path.join(temp_dir, filename)
                            
                            if os.path.isfile(file_path):
                                # Provjera sumnjivih ekstenzija
                                file_ext = os.path.splitext(filename)[1].lower()
                                if file_ext in self.suspicious_extensions:
                                    activities.append({
                                        'action': 'created',
                                        'path': file_path,
                                        'filename': filename,
                                        'timestamp': datetime.now().isoformat()
                                    })
                    except (OSError, PermissionError):
                        continue
            
            return activities
            
        except Exception as e:
            self.log_error(f"Greška pri provjeri fajl aktivnosti: {e}")
            return []
    
    def check_network_activities(self):
        """Provjera mrežnih aktivnosti"""
        try:
            activities = []
            current_connections = set()
            
            for conn in psutil.net_connections():
                try:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        conn_key = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                        current_connections.add(conn_key)
                        
                        # Provjera da li je nova konekcija
                        if conn_key not in self.previous_connections:
                            activity = {
                                'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                                'status': conn.status,
                                'timestamp': datetime.now().isoformat()
                            }
                            activities.append(activity)
                
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Ažuriranje prethodnog stanja
            self.previous_connections = current_connections
            
            return activities
            
        except Exception as e:
            self.log_error(f"Greška pri provjeri mrežnih aktivnosti: {e}")
            return []
    
    def check_system_events(self):
        """Provjera sistemskih događaja"""
        try:
            events = []
            
            # Provjera CPU korištenja
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 80:
                events.append({
                    'type': 'high_cpu',
                    'description': f"Visoko korištenje CPU: {cpu_percent:.1f}%",
                    'severity': 'warning',
                    'timestamp': datetime.now().isoformat()
                })
            
            # Provjera memorije
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                events.append({
                    'type': 'high_memory',
                    'description': f"Visoko korištenje memorije: {memory.percent:.1f}%",
                    'severity': 'warning',
                    'timestamp': datetime.now().isoformat()
                })
            
            # Provjera diska
            disk = psutil.disk_usage('/')
            if disk.percent > 95:
                events.append({
                    'type': 'low_disk',
                    'description': f"Nizak prostor na disku: {disk.percent:.1f}%",
                    'severity': 'warning',
                    'timestamp': datetime.now().isoformat()
                })
            
            # Provjera broja procesa
            process_count = len(psutil.pids())
            if process_count > 1000:
                events.append({
                    'type': 'high_process_count',
                    'description': f"Visok broj procesa: {process_count}",
                    'severity': 'info',
                    'timestamp': datetime.now().isoformat()
                })
            
            return events
            
        except Exception as e:
            self.log_error(f"Greška pri provjeri sistemskih događaja: {e}")
            return []
    
    def get_system_info(self):
        """Dobijanje informacija o sistemu"""
        try:
            info = {
                'platform': os.name,
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_total': psutil.disk_usage('/').total,
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
            
            # Dodatne informacije za Windows
            if os.name == 'nt':
                try:
                    import platform
                    info['windows_version'] = platform.platform()
                except:
                    pass
            
            return info
            
        except Exception as e:
            self.log_error(f"Greška pri dobijanju informacija o sistemu: {e}")
            return {}
    
    def get_process_details(self, pid):
        """Dobijanje detalja o procesu"""
        try:
            proc = psutil.Process(pid)
            
            details = {
                'pid': proc.pid,
                'name': proc.name(),
                'cmdline': proc.cmdline(),
                'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                'cpu_percent': proc.cpu_percent(),
                'memory_percent': proc.memory_percent(),
                'status': proc.status(),
                'num_threads': proc.num_threads(),
                'connections': []
            }
            
            # Mrežne konekcije
            try:
                connections = proc.connections()
                for conn in connections:
                    conn_info = {
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status
                    }
                    details['connections'].append(conn_info)
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
            
            return details
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            self.log_error(f"Greška pri dobijanju detalja o procesu {pid}: {e}")
            return None
    
    def get_network_info(self):
        """Dobijanje informacija o mreži"""
        try:
            info = {
                'interfaces': [],
                'connections': [],
                'stats': {}
            }
            
            # Mrežni interfejsi
            for interface, addresses in psutil.net_if_addrs().items():
                interface_info = {
                    'name': interface,
                    'addresses': []
                }
                
                for addr in addresses:
                    address_info = {
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
                    interface_info['addresses'].append(address_info)
                
                info['interfaces'].append(interface_info)
            
            # Mrežne konekcije
            for conn in psutil.net_connections():
                try:
                    conn_info = {
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    info['connections'].append(conn_info)
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Mrežne statistike
            net_stats = psutil.net_io_counters()
            info['stats'] = {
                'bytes_sent': net_stats.bytes_sent,
                'bytes_recv': net_stats.bytes_recv,
                'packets_sent': net_stats.packets_sent,
                'packets_recv': net_stats.packets_recv
            }
            
            return info
            
        except Exception as e:
            self.log_error(f"Greška pri dobijanju informacija o mreži: {e}")
            return {}
    
    def get_disk_info(self):
        """Dobijanje informacija o disku"""
        try:
            info = {
                'partitions': [],
                'usage': {}
            }
            
            # Particije
            for partition in psutil.disk_partitions():
                partition_info = {
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'opts': partition.opts
                }
                info['partitions'].append(partition_info)
            
            # Korištenje diska
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    info['usage'][partition.mountpoint] = {
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    }
                except (OSError, PermissionError):
                    continue
            
            return info
            
        except Exception as e:
            self.log_error(f"Greška pri dobijanju informacija o disku: {e}")
            return {}
    
    def kill_process(self, pid):
        """Ubijanje procesa"""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            
            # Čekanje da se proces završi
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()
            
            self.log_info(f"Proces {pid} ubijen")
            return True
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            self.log_error(f"Greška pri ubijanju procesa {pid}: {e}")
            return False
    
    def quarantine_file(self, file_path, quarantine_dir):
        """Kvarentiniranje fajla"""
        try:
            if not os.path.exists(file_path):
                return False
            
            # Kreiranje kvarentin direktorijuma
            os.makedirs(quarantine_dir, exist_ok=True)
            
            # Generisanje imena za kvarentin
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"quarantine_{timestamp}_{filename}"
            quarantine_path = os.path.join(quarantine_dir, quarantine_name)
            
            # Premještanje fajla
            os.rename(file_path, quarantine_path)
            
            self.log_info(f"Fajl {file_path} kvarentiniran u {quarantine_path}")
            return True
            
        except Exception as e:
            self.log_error(f"Greška pri kvarentiniranju fajla {file_path}: {e}")
            return False
    
    def generate_report(self):
        """Generisanje izvještaja o sistemu"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'system_info': self.get_system_info(),
                'network_info': self.get_network_info(),
                'disk_info': self.get_disk_info(),
                'processes': [],
                'suspicious_activities': []
            }
            
            # Top procesi po korištenju resursa
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    if proc_info['cpu_percent'] > 0 or proc_info['memory_percent'] > 0:
                        processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Sortiranje po CPU korištenju
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            report['processes'] = processes[:10]
            
            # Sumnjive aktivnosti
            suspicious_processes = self.check_suspicious_processes()
            report['suspicious_activities'].extend(suspicious_processes)
            
            return report
            
        except Exception as e:
            self.log_error(f"Greška pri generisanju izvještaja: {e}")
            return {} 