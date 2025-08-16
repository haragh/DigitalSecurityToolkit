#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Logger modul za Digital Security Toolkit
"""

import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler

def setup_logger(name, log_file, level=logging.INFO):
    """
    Postavljanje logger-a sa rotacijom fajlova
    
    Args:
        name (str): Ime logger-a
        log_file (str): Putanja do log fajla
        level: Nivo logovanja
    
    Returns:
        logging.Logger: Konfigurisan logger
    """
    
    # Kreiranje direktorijuma ako ne postoji
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    # Kreiranje logger-a
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Provjera da li logger već ima handler-e
    if logger.handlers:
        return logger
    
    # Formatter za log poruke
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler sa rotacijom (max 10MB, 5 backup fajlova)
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)  # Samo warning i error u konzoli
    console_handler.setFormatter(formatter)
    
    # Dodavanje handler-a
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def get_logger(name):
    """
    Dobijanje postojećeg logger-a
    
    Args:
        name (str): Ime logger-a
    
    Returns:
        logging.Logger: Logger
    """
    return logging.getLogger(name)

class LoggerMixin:
    """Mixin klasa za dodavanje logger-a u druge klase"""
    
    def __init__(self, logger_name=None):
        if logger_name:
            self.logger = get_logger(logger_name)
        else:
            self.logger = get_logger(self.__class__.__name__)
    
    def log_info(self, message):
        """Log info poruke"""
        self.logger.info(message)
    
    def log_warning(self, message):
        """Log warning poruke"""
        self.logger.warning(message)
    
    def log_error(self, message):
        """Log error poruke"""
        self.logger.error(message)
    
    def log_debug(self, message):
        """Log debug poruke"""
        self.logger.debug(message) 