import logging
import sys
from datetime import datetime

def setup_logger(verbose=False):
    """Setup logging configuration"""
    
    # Create logger
    logger = logging.getLogger('security_tester')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Create file handler
    file_handler = logging.FileHandler(
        f'security_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    )
    file_handler.setLevel(logging.DEBUG)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger