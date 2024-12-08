
##
import logging

def setup_logger():
    """
    Logger'ı ayarlayan fonksiyon.
    """
    logger = logging.getLogger("firewall_logger")
    logger.setLevel(logging.DEBUG)
    
    # File handler'ı ayarla
    file_handler = logging.FileHandler('firewall.log')
    file_handler.setLevel(logging.DEBUG)
    
    # Formatı ayarla
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    
    # Logger'a handler'ı ekle
    logger.addHandler(file_handler)
    
    return logger

def start_logger():
    """
    Logger'ı başlatan fonksiyon.
    """
    logger = setup_logger()
    logger.info("Logging system initialized.")
    return logger

