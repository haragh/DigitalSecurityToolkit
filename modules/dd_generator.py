#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modul za generisanje DD slike sa validnim fajlovima
Ovdje se kreira prazna DD slika i upisuju se validni fajlovi (PDF, JPG, TXT, itd.)
"""

import os
import random
from datetime import datetime

# Maksimalna veličina DD slike (500MB)
VELICINA_DD_SLIKE = 500 * 1024 * 1024
# Maksimalna veličina jednog fajla (100MB)
MAX_FAJL_VELICINA = 100 * 1024 * 1024

# Lista formata koje podržavamo
PODRZANI_FORMATI = ['pdf', 'jpg', 'txt']

# Glavna funkcija za generisanje DD slike
# putanja_dd - gdje će biti kreirana slika
# fajlovi_info - lista dictova: {'tip': 'pdf', 'velicina': 1234567, 'ime': 'nesto.pdf'}
def generisi_dd_sliku(putanja_dd, fajlovi_info):
    """
    Generiše DD sliku i upisuje validne fajlove na nasumične lokacije.
    """
    # Kreiraj praznu sliku
    with open(putanja_dd, 'wb') as f:
        f.write(b'\x00' * VELICINA_DD_SLIKE)
    
    # Upis fajlova na nasumične lokacije
    with open(putanja_dd, 'r+b') as f:
        zauzete_lokacije = []
        for info in fajlovi_info:
            tip = info['tip']
            velicina = min(info['velicina'], MAX_FAJL_VELICINA)
            ime = info['ime']
            # Generiši sadržaj fajla
            if tip == 'pdf':
                sadrzaj = generisi_pdf(ime, velicina)
            elif tip == 'jpg':
                sadrzaj = generisi_jpg(ime, velicina)
            elif tip == 'txt':
                sadrzaj = generisi_txt(ime, velicina)
            else:
                continue
            # Pronađi slobodnu lokaciju
            while True:
                offset = random.randint(1024*1024, VELICINA_DD_SLIKE - velicina - 1)
                konflikt = False
                for (start, end) in zauzete_lokacije:
                    if not (offset + velicina < start or offset > end):
                        konflikt = True
                        break
                if not konflikt:
                    break
            # Upisi fajl
            f.seek(offset)
            f.write(sadrzaj)
            zauzete_lokacije.append((offset, offset+velicina-1))
            # (Opcionalno) upisi metapodatke na početak fajla
    # Kraj
    return True

# Funkcija za generisanje PDF fajla
# ime - ime fajla, velicina - veličina u bajtima
def generisi_pdf(ime, velicina):
    """
    Generiše validan PDF fajl sa osnovnim sadržajem i metapodacima.
    """
    # Minimalni PDF header
    header = b'%PDF-1.4\n'
    body = f"1 0 obj\n<< /Title ({ime}) /Creator (DD Generator) /CreationDate ({datetime.now()}) >>\nendobj\n".encode('utf-8')
    # Dodaj osnovni sadržaj
    content = b"2 0 obj\n<< /Length 20 >>\nstream\nOvo je test PDF fajl.\nendstream\nendobj\n"
    # Popuni do željene veličine
    ostatak = velicina - (len(header) + len(body) + len(content) + 10)
    if ostatak > 0:
        padding = b'A' * ostatak
    else:
        padding = b''
    kraj = b'\n%%EOF\n'
    return header + body + content + padding + kraj

# Funkcija za generisanje JPG fajla
def generisi_jpg(ime, velicina):
    """
    Generiše validan JPG fajl sa osnovnim headerom i podacima.
    """
    # Minimalni JPEG header
    header = b'\xff\xd8\xff\xe0' + b'\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00'
    # Dodaj osnovni sadržaj
    content = b'\xff\xdb' + b'\x00' * 64 + b'\xff\xc0' + b'\x00' * 32
    ostatak = velicina - (len(header) + len(content) + 2)
    if ostatak > 0:
        padding = b'B' * ostatak
    else:
        padding = b''
    kraj = b'\xff\xd9'
    return header + content + padding + kraj

# Funkcija za generisanje TXT fajla
def generisi_txt(ime, velicina):
    """
    Generiše validan TXT fajl sa osnovnim sadržajem.
    """
    header = f"Ovo je test TXT fajl: {ime}\nGenerisano: {datetime.now()}\n".encode('utf-8')
    ostatak = velicina - len(header)
    if ostatak > 0:
        padding = ("C" * ostatak).encode('utf-8')
    else:
        padding = b''
    return header + padding 