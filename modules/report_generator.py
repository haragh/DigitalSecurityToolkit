#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Report Generator Module - Generator izvještaja
"""

import os
import json
import threading
from datetime import datetime
from utils.logger import LoggerMixin

class ReportGenerator(LoggerMixin):
    """Klasa za generisanje izvještaja"""
    
    def __init__(self, config, logger):
        super().__init__("ReportGenerator")
        self.config = config
        self.logger = logger
        self.stop_generation = False
        
        # Template-ovi
        self.templates = {
            'comprehensive': self.get_comprehensive_template(),
            'summary': self.get_summary_template(),
            'detailed': self.get_detailed_template()
        }
    
    def generate_report(self, report_type, output_format, output_dir, options, data_sources, progress_callback=None):
        """
        Generisanje izvještaja
        
        Args:
            report_type (str): Tip izvještaja (comprehensive, summary, detailed)
            output_format (str): Format izvještaja (pdf, html, json)
            output_dir (str): Output direktorijum
            options (dict): Opcije za generisanje
            data_sources (list): Izvori podataka
            progress_callback (function): Callback za progress
        
        Returns:
            str: Putanja do generisanog izvještaja
        """
        try:
            self.stop_generation = False
            
            # Kreiranje output direktorijuma
            os.makedirs(output_dir, exist_ok=True)
            
            # Generisanje imena fajla
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{report_type}_{timestamp}.{output_format}"
            output_path = os.path.join(output_dir, filename)
            
            # Prikupljanje podataka
            if progress_callback:
                progress_callback(10, "Prikupljanje podataka...")
            
            data = self.collect_data(data_sources)
            
            # Generisanje sadržaja
            if progress_callback:
                progress_callback(30, "Generisanje sadržaja...")
            
            content = self.generate_content(report_type, data, options)
            
            # Čuvanje izvještaja
            if progress_callback:
                progress_callback(70, "Čuvanje izvještaja...")
            
            if output_format == 'pdf':
                self.save_pdf_report(content, output_path)
            elif output_format == 'html':
                self.save_html_report(content, output_path)
            elif output_format == 'json':
                self.save_json_report(content, output_path)
            else:
                raise ValueError(f"Nepodržan format: {output_format}")
            
            if progress_callback:
                progress_callback(100, "Izvještaj generisan")
            
            self.log_info(f"Izvještaj generisan: {output_path}")
            return output_path
            
        except Exception as e:
            self.log_error(f"Greška pri generisanju izvještaja: {e}")
            return None
    
    def collect_data(self, data_sources):
        """Prikupljanje podataka iz različitih izvora"""
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'system_info': self.get_system_info(),
                'file_recovery': {},
                'yara_scan': {},
                'integrity_check': {},
                'timeline': {},
                'monitoring': {}
            }
            
            # Prikupljanje podataka iz svakog izvora
            for source in data_sources:
                if source == 'file_recovery':
                    data['file_recovery'] = self.get_file_recovery_data()
                elif source == 'yara_scan':
                    data['yara_scan'] = self.get_yara_scan_data()
                elif source == 'integrity_check':
                    data['integrity_check'] = self.get_integrity_check_data()
                elif source == 'timeline':
                    data['timeline'] = self.get_timeline_data()
                elif source == 'monitoring':
                    data['monitoring'] = self.get_monitoring_data()
            
            return data
            
        except Exception as e:
            self.log_error(f"Greška pri prikupljanju podataka: {e}")
            return {}
    
    def get_system_info(self):
        """Dobijanje informacija o sistemu"""
        try:
            import platform
            import psutil
            
            return {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
        except Exception as e:
            self.log_error(f"Greška pri dobijanju informacija o sistemu: {e}")
            return {}
    
    def get_file_recovery_data(self):
        """Dobijanje podataka o oporavku fajlova"""
        try:
            recovered_dir = "recovered_files"
            if not os.path.exists(recovered_dir):
                return {
                    'recovered_files': 0,
                    'total_size': 0,
                    'formats_found': []
                }
            
            recovered_files = []
            total_size = 0
            formats_found = set()
            
            for file in os.listdir(recovered_dir):
                file_path = os.path.join(recovered_dir, file)
                if os.path.isfile(file_path):
                    file_size = os.path.getsize(file_path)
                    file_ext = os.path.splitext(file)[1].lower()
                    
                    recovered_files.append({
                        'name': file,
                        'size': file_size,
                        'extension': file_ext
                    })
                    total_size += file_size
                    formats_found.add(file_ext)
            
            return {
                'recovered_files': len(recovered_files),
                'total_size': total_size,
                'formats_found': list(formats_found),
                'files': recovered_files
            }
        except Exception as e:
            self.log_error(f"Greška pri dobijanju podataka o oporavku: {e}")
            return {
                'recovered_files': 0,
                'total_size': 0,
                'formats_found': []
            }
    
    def get_yara_scan_data(self):
        """Dobijanje podataka o YARA skeniranju"""
        try:
            # Čitanje iz logova
            log_file = "logs/dst.log"
            scanned_files = 0
            detected_threats = 0
            rules_used = 0
            
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if 'YARA' in line and 'skeniran' in line:
                            scanned_files += 1
                        if 'detektovan' in line.lower() or 'threat' in line.lower():
                            detected_threats += 1
                        if 'rule' in line.lower() and 'yara' in line.lower():
                            rules_used += 1
            
            # Ako nema podataka u logovima, provjeri rules direktorij
            if rules_used == 0:
                rules_dir = "rules"
                if os.path.exists(rules_dir):
                    rules_used = len([f for f in os.listdir(rules_dir) if f.endswith('.yar')])
            
            return {
                'scanned_files': scanned_files,
                'detected_threats': detected_threats,
                'rules_used': rules_used
            }
        except Exception as e:
            self.log_error(f"Greška pri dobijanju podataka o YARA skeniranju: {e}")
            return {
                'scanned_files': 0,
                'detected_threats': 0,
                'rules_used': 0
            }
    
    def get_integrity_check_data(self):
        """Dobijanje podataka o provjeri integriteta"""
        try:
            # Čitanje iz logova
            log_file = "logs/dst.log"
            checked_files = 0
            valid_files = 0
            corrupted_files = 0
            
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if 'integritet' in line.lower() or 'integrity' in line.lower():
                            checked_files += 1
                        if 'valid' in line.lower() or 'ispravan' in line.lower():
                            valid_files += 1
                        if 'corrupt' in line.lower() or 'ostecen' in line.lower():
                            corrupted_files += 1
            
            return {
                'checked_files': checked_files,
                'valid_files': valid_files,
                'corrupted_files': corrupted_files
            }
        except Exception as e:
            self.log_error(f"Greška pri dobijanju podataka o integritetu: {e}")
            return {
                'checked_files': 0,
                'valid_files': 0,
                'corrupted_files': 0
            }
    
    def get_timeline_data(self):
        """Dobijanje podataka o vremenskoj liniji"""
        try:
            # Čitanje iz logova
            log_file = "logs/dst.log"
            total_activities = 0
            time_period = {}
            anomalies = []
            
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if 'aktivnost' in line.lower() or 'activity' in line.lower():
                            total_activities += 1
                        if 'anomalija' in line.lower() or 'anomaly' in line.lower():
                            anomalies.append(line.strip())
            
            return {
                'total_activities': total_activities,
                'time_period': time_period,
                'anomalies': anomalies
            }
        except Exception as e:
            self.log_error(f"Greška pri dobijanju podataka o vremenskoj liniji: {e}")
            return {
                'total_activities': 0,
                'time_period': {},
                'anomalies': []
            }
    
    def get_monitoring_data(self):
        """Dobijanje podataka o nadzoru"""
        try:
            # Čitanje iz logova
            log_file = "logs/dst.log"
            monitoring_duration = 0
            events_detected = 0
            suspicious_activities = []
            
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if 'monitoring' in line.lower() or 'nadzor' in line.lower():
                            events_detected += 1
                        if 'sumnjiv' in line.lower() or 'suspicious' in line.lower():
                            suspicious_activities.append(line.strip())
            
            return {
                'monitoring_duration': monitoring_duration,
                'events_detected': events_detected,
                'suspicious_activities': suspicious_activities
            }
        except Exception as e:
            self.log_error(f"Greška pri dobijanju podataka o nadzoru: {e}")
            return {
                'monitoring_duration': 0,
                'events_detected': 0,
                'suspicious_activities': []
            }
    
    def generate_content(self, report_type, data, options):
        """Generisanje sadržaja izvještaja"""
        try:
            template = self.templates.get(report_type, self.templates['summary'])
            
            # Popunjavanje template-a
            content = template.copy()
            content['data'] = data
            content['options'] = options
            content['generation_time'] = datetime.now().isoformat()
            
            return content
            
        except Exception as e:
            self.log_error(f"Greška pri generisanju sadržaja: {e}")
            return {}
    
    def save_pdf_report(self, content, output_path):
        """Čuvanje PDF izvještaja"""
        try:
            from fpdf import FPDF
            
            pdf = FPDF()
            pdf.add_page()
            
            # Naslov
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 10, 'Digital Security Toolkit - Izvjestaj', ln=True, align='C')
            pdf.ln(10)
            
            # Informacije o sistemu
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, 'Informacije o sistemu:', ln=True)
            pdf.set_font('Arial', '', 10)
            
            system_info = content.get('data', {}).get('system_info', {})
            for key, value in system_info.items():
                pdf.cell(0, 8, f"{key}: {value}", ln=True)
            
            pdf.ln(10)
            
            # Rezultati skeniranja
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, 'Rezultati skeniranja:', ln=True)
            pdf.set_font('Arial', '', 10)
            
            # File Recovery
            file_recovery = content.get('data', {}).get('file_recovery', {})
            pdf.cell(0, 8, f"Oporavljeni fajlovi: {file_recovery.get('recovered_files', 0)}", ln=True)
            
            # YARA Scan
            yara_scan = content.get('data', {}).get('yara_scan', {})
            pdf.cell(0, 8, f"Detektovane prijetnje: {yara_scan.get('detected_threats', 0)}", ln=True)
            
            # Integrity Check
            integrity_check = content.get('data', {}).get('integrity_check', {})
            pdf.cell(0, 8, f"Provjereni fajlovi: {integrity_check.get('checked_files', 0)}", ln=True)
            
            # Timeline
            timeline = content.get('data', {}).get('timeline', {})
            pdf.cell(0, 8, f"Aktivnosti: {timeline.get('total_activities', 0)}", ln=True)
            
            # Monitoring
            monitoring = content.get('data', {}).get('monitoring', {})
            pdf.cell(0, 8, f"Detektovani dogadjaji: {monitoring.get('events_detected', 0)}", ln=True)
            
            pdf.ln(10)
            
            # Preporuke
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, 'Preporuke:', ln=True)
            pdf.set_font('Arial', '', 10)
            
            recommendations = self.generate_recommendations(content)
            for rec in recommendations:
                pdf.cell(0, 8, f"- {rec}", ln=True)
            
            # Čuvanje
            pdf.output(output_path)
            
        except Exception as e:
            self.log_error(f"Greška pri čuvanju PDF izvještaja: {e}")
            raise
    
    def save_html_report(self, content, output_path):
        """Čuvanje HTML izvještaja"""
        try:
            html_content = self.generate_html_content(content)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
        except Exception as e:
            self.log_error(f"Greška pri čuvanju HTML izvještaja: {e}")
            raise
    
    def save_json_report(self, content, output_path):
        """Čuvanje JSON izvještaja"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(content, f, indent=4, ensure_ascii=False)
            
        except Exception as e:
            self.log_error(f"Greška pri čuvanju JSON izvještaja: {e}")
            raise
    
    def generate_html_content(self, content):
        """Generisanje HTML sadržaja"""
        try:
            html = f"""
<!DOCTYPE html>
<html lang="bs">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Digital Security Toolkit - Izvještaj</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            text-align: center;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #007bff;
            margin-top: 30px;
        }}
        .section {{
            margin: 20px 0;
            padding: 15px;
            border-left: 4px solid #007bff;
            background-color: #f8f9fa;
        }}
        .metric {{
            display: inline-block;
            margin: 10px;
            padding: 10px;
            background-color: #e9ecef;
            border-radius: 5px;
            min-width: 150px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }}
        .metric-label {{
            font-size: 12px;
            color: #666;
        }}
        .recommendation {{
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .warning {{
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .success {{
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #007bff;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Digital Security Toolkit - Izvještaj</h1>
        
        <div class="section">
            <h2>Informacije o izvještaju</h2>
            <p><strong>Datum generisanja:</strong> {content.get('generation_time', 'N/A')}</p>
            <p><strong>Tip izvještaja:</strong> {content.get('report_type', 'N/A')}</p>
        </div>
        
        <div class="section">
            <h2>Sažetak</h2>
            <div class="metric">
                <div class="metric-value">{content.get('data', {}).get('file_recovery', {}).get('recovered_files', 0)}</div>
                <div class="metric-label">Oporavljeni fajlovi</div>
            </div>
            <div class="metric">
                <div class="metric-value">{content.get('data', {}).get('yara_scan', {}).get('detected_threats', 0)}</div>
                <div class="metric-label">Detektovane prijetnje</div>
            </div>
            <div class="metric">
                <div class="metric-value">{content.get('data', {}).get('integrity_check', {}).get('checked_files', 0)}</div>
                <div class="metric-label">Provjereni fajlovi</div>
            </div>
            <div class="metric">
                <div class="metric-value">{content.get('data', {}).get('timeline', {}).get('total_activities', 0)}</div>
                <div class="metric-label">Aktivnosti</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Detaljni rezultati</h2>
            
            <h3>Oporavak podataka</h3>
            <table>
                <tr>
                    <th>Metrika</th>
                    <th>Vrijednost</th>
                </tr>
                <tr>
                    <td>Oporavljeni fajlovi</td>
                    <td>{content.get('data', {}).get('file_recovery', {}).get('recovered_files', 0)}</td>
                </tr>
                <tr>
                    <td>Ukupna veličina</td>
                    <td>{content.get('data', {}).get('file_recovery', {}).get('total_size', 0)} bajtova</td>
                </tr>
            </table>
            
            <h3>YARA skeniranje</h3>
            <table>
                <tr>
                    <th>Metrika</th>
                    <th>Vrijednost</th>
                </tr>
                <tr>
                    <td>Skenirani fajlovi</td>
                    <td>{content.get('data', {}).get('yara_scan', {}).get('scanned_files', 0)}</td>
                </tr>
                <tr>
                    <td>Detektovane prijetnje</td>
                    <td>{content.get('data', {}).get('yara_scan', {}).get('detected_threats', 0)}</td>
                </tr>
                <tr>
                    <td>Korištena pravila</td>
                    <td>{content.get('data', {}).get('yara_scan', {}).get('rules_used', 0)}</td>
                </tr>
            </table>
            
            <h3>Provjera integriteta</h3>
            <table>
                <tr>
                    <th>Metrika</th>
                    <th>Vrijednost</th>
                </tr>
                <tr>
                    <td>Provjereni fajlovi</td>
                    <td>{content.get('data', {}).get('integrity_check', {}).get('checked_files', 0)}</td>
                </tr>
                <tr>
                    <td>Validni fajlovi</td>
                    <td>{content.get('data', {}).get('integrity_check', {}).get('valid_files', 0)}</td>
                </tr>
                <tr>
                    <td>Oštećeni fajlovi</td>
                    <td>{content.get('data', {}).get('integrity_check', {}).get('corrupted_files', 0)}</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Preporuke</h2>
"""
            
            recommendations = self.generate_recommendations(content)
            for rec in recommendations:
                html += f'            <div class="recommendation">• {rec}</div>\n'
            
            html += """
        </div>
        
        <div class="section">
            <h2>Zaključak</h2>
            <p>Ovaj izvještaj je generisan automatski od strane Digital Security Toolkit aplikacije. 
            Preporučuje se redovna provjera sistema i ažuriranje sigurnosnih mjera.</p>
        </div>
    </div>
</body>
</html>
"""
            
            return html
            
        except Exception as e:
            self.log_error(f"Greška pri generisanju HTML sadržaja: {e}")
            return "<html><body><h1>Greška pri generisanju izvještaja</h1></body></html>"
    
    def generate_recommendations(self, content):
        """Generisanje preporuka na osnovu rezultata"""
        try:
            recommendations = []
            
            # Preporuke na osnovu YARA skeniranja
            detected_threats = content.get('data', {}).get('yara_scan', {}).get('detected_threats', 0)
            if detected_threats > 0:
                recommendations.append(f"Pronadjeno je {detected_threats} potencijalnih prijetnji. Preporucuje se detaljna analiza.")
            
            # Preporuke na osnovu integriteta
            corrupted_files = content.get('data', {}).get('integrity_check', {}).get('corrupted_files', 0)
            if corrupted_files > 0:
                recommendations.append(f"Pronadjeno je {corrupted_files} ostecenih fajlova. Preporucuje se oporavak podataka.")
            
            # Opcenite preporuke
            recommendations.extend([
                "Redovno azurirajte antivirus softver",
                "Koristite jake lozinke i dvofaktorsku autentifikaciju",
                "Redovno pravdajte backup podataka",
                "Pratite sistemske logove za sumnjive aktivnosti",
                "Koristite firewall i VPN za dodatnu zastitu"
            ])
            
            return recommendations
            
        except Exception as e:
            self.log_error(f"Greska pri generisanju preporuka: {e}")
            return ["Greska pri generisanju preporuka"]
    
    def get_comprehensive_template(self):
        """Template za sveobuhvatan izvještaj"""
        return {
            'report_type': 'comprehensive',
            'sections': [
                'executive_summary',
                'system_information',
                'file_recovery_results',
                'yara_scan_results',
                'integrity_check_results',
                'timeline_analysis',
                'monitoring_results',
                'recommendations',
                'appendix'
            ]
        }
    
    def get_summary_template(self):
        """Template za sažetak izvještaj"""
        return {
            'report_type': 'summary',
            'sections': [
                'executive_summary',
                'key_findings',
                'recommendations'
            ]
        }
    
    def get_detailed_template(self):
        """Template za detaljan izvještaj"""
        return {
            'report_type': 'detailed',
            'sections': [
                'executive_summary',
                'methodology',
                'system_information',
                'detailed_results',
                'analysis',
                'recommendations',
                'technical_details'
            ]
        }
    
    def stop_generation(self):
        """Zaustavljanje generisanja"""
        self.stop_generation = True
        self.log_info("Generisanje izvještaja zaustavljeno") 