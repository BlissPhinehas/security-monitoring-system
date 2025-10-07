"""
Configuration management for Threat Intelligence system
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Application configuration"""
    
    # Base paths
    BASE_DIR = Path(__file__).parent.parent
    DATA_DIR = BASE_DIR / "data"
    REPORTS_DIR = DATA_DIR / "reports"
    CACHE_DIR = DATA_DIR / "cache"
    
    # API Keys
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    
    # Application settings
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    REPORT_FORMAT = os.getenv("REPORT_FORMAT", "json")
    CACHE_DURATION = int(os.getenv("CACHE_DURATION", "3600"))  # 1 hour
    
    # Threat detection thresholds
    IP_REPUTATION_THRESHOLD = int(os.getenv("IP_REPUTATION_THRESHOLD", "75"))
    ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_DETECTION_THRESHOLD", "0.7"))
    
    # API endpoints
    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
    VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses"
    VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files"
    
    @classmethod
    def ensure_directories(cls):
        """Create necessary directories if they don't exist"""
        cls.DATA_DIR.mkdir(exist_ok=True)
        cls.REPORTS_DIR.mkdir(exist_ok=True)
        cls.CACHE_DIR.mkdir(exist_ok=True)

# Ensure directories exist on import
Config.ensure_directories()
